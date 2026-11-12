#!/usr/bin/env python3
"""Hide AES-GCM encrypted messages inside PNG images using LSB steganography.

Header layout (36 bytes, embedded before the ciphertext):

    magic     4 bytes   b"STG1"
    salt     16 bytes   PBKDF2 salt
    nonce    12 bytes   AES-GCM nonce
    length    4 bytes   ciphertext length, big-endian uint32

The header + ciphertext are written into the least-significant bit of each
RGB channel, in row-major order. The magic, salt and nonce are also used as
AES-GCM associated data, so tampering with the header fails authentication.
"""

from __future__ import annotations

import argparse
import getpass
import secrets
import struct
import sys
import tempfile
from pathlib import Path
from typing import Iterator

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from PIL import Image, UnidentifiedImageError

MAGIC = b"STG1"
SALT_LEN = 16
NONCE_LEN = 12
LENGTH_LEN = 4
HEADER_LEN = len(MAGIC) + SALT_LEN + NONCE_LEN + LENGTH_LEN
KDF_ITERATIONS = 600_000
KEY_LEN = 32
TAG_LEN = 16


class StegoError(Exception):
    """Raised for expected, user-facing failures."""


def _capacity_bytes(image: Image.Image) -> int:
    return (image.width * image.height * 3) // 8


def _bits(data: bytes) -> Iterator[int]:
    for byte in data:
        for shift in range(7, -1, -1):
            yield (byte >> shift) & 1


def _take_bytes(bits: Iterator[int], count: int) -> bytes:
    out = bytearray()
    accumulator = 0
    bit_count = 0
    for bit in bits:
        accumulator = (accumulator << 1) | bit
        bit_count += 1
        if bit_count == 8:
            out.append(accumulator)
            accumulator = 0
            bit_count = 0
            if len(out) == count:
                return bytes(out)
    raise StegoError(
        f"Image ended after {len(out)} of {count} bytes. "
        "It does not contain a complete hidden payload."
    )


def _extract_bits(image: Image.Image) -> Iterator[int]:
    pixels = image.load()
    for y in range(image.height):
        for x in range(image.width):
            red, green, blue = pixels[x, y]
            yield red & 1
            yield green & 1
            yield blue & 1


def _embed(image: Image.Image, payload: bytes) -> None:
    capacity = _capacity_bytes(image)
    if len(payload) > capacity:
        raise StegoError(
            f"Payload is {len(payload)} bytes but this image can hold at most "
            f"{capacity} bytes ({image.width}x{image.height})."
        )

    pixels = image.load()
    stream = _bits(payload)
    exhausted = False
    for y in range(image.height):
        if exhausted:
            break
        for x in range(image.width):
            red, green, blue = pixels[x, y]
            channels = [red, green, blue]
            for index in range(3):
                try:
                    bit = next(stream)
                except StopIteration:
                    exhausted = True
                    break
                channels[index] = (channels[index] & 0xFE) | bit
            pixels[x, y] = (channels[0], channels[1], channels[2])
            if exhausted:
                break


def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def _load_png(path: Path, *, for_write: bool) -> Image.Image:
    if path.suffix.lower() != ".png":
        raise StegoError(
            "Use a PNG. JPEG/WebP re-encode pixels and destroy the hidden bits."
        )
    if not path.exists():
        raise StegoError(f"File not found: {path}")
    try:
        image = Image.open(path)
    except UnidentifiedImageError as exc:
        raise StegoError(f"Not a readable image: {path}") from exc
    if image.mode != "RGB":
        image = image.convert("RGB")
    return image


def encrypt(image_path: Path, output_path: Path, message: bytes, password: str) -> None:
    if not message:
        raise StegoError("Message is empty.")
    image = _load_png(image_path, for_write=True)

    salt = secrets.token_bytes(SALT_LEN)
    nonce = secrets.token_bytes(NONCE_LEN)
    key = _derive_key(password, salt)
    associated = MAGIC + salt + nonce
    ciphertext = AESGCM(key).encrypt(nonce, message, associated)

    payload = associated + struct.pack(">I", len(ciphertext)) + ciphertext
    _embed(image, payload)
    image.save(output_path, format="PNG")
    print(
        f"Encrypted {len(message)} bytes into {output_path} "
        f"({len(payload)} bytes embedded, {_capacity_bytes(image)} byte capacity)."
    )


def decrypt(image_path: Path, password: str, output_path: Path | None) -> bytes:
    image = _load_png(image_path, for_write=False)
    stream = _extract_bits(image)

    header = _take_bytes(stream, HEADER_LEN)
    if header[: len(MAGIC)] != MAGIC:
        raise StegoError(
            "No hidden message found. The image is not a STG1 carrier, "
            "or it was resized/re-encoded."
        )

    salt = header[len(MAGIC) : len(MAGIC) + SALT_LEN]
    nonce = header[len(MAGIC) + SALT_LEN : len(MAGIC) + SALT_LEN + NONCE_LEN]
    (length,) = struct.unpack(">I", header[HEADER_LEN - LENGTH_LEN :])

    capacity = _capacity_bytes(image) - HEADER_LEN
    if length == 0 or length > capacity:
        raise StegoError(
            f"Invalid payload length {length} (capacity is {capacity} bytes). "
            "The image is corrupted or does not contain a hidden message."
        )

    ciphertext = _take_bytes(stream, length)
    key = _derive_key(password, salt)
    try:
        message = AESGCM(key).decrypt(nonce, ciphertext, MAGIC + salt + nonce)
    except InvalidTag as exc:
        raise StegoError(
            "Decryption failed: wrong password, or the image was modified."
        ) from exc

    if output_path is not None:
        output_path.write_bytes(message)
        print(f"Wrote {len(message)} bytes to {output_path}.")
    return message


def _password(value: str | None) -> str:
    if value is not None:
        return value
    first = getpass.getpass("Password: ")
    second = getpass.getpass("Repeat password: ")
    if first != second:
        raise StegoError("Passwords do not match.")
    if not first:
        raise StegoError("Password is empty.")
    return first


def selftest() -> None:
    """Round-trip test on a generated image; also checks the wrong password."""
    with tempfile.TemporaryDirectory() as tmp:
        cover = Path(tmp) / "cover.png"
        carrier = Path(tmp) / "carrier.png"

        image = Image.new("RGB", (256, 256))
        pixels = image.load()
        for y in range(256):
            for x in range(256):
                pixels[x, y] = (x, y, (x + y) % 256)
        image.save(cover, format="PNG")

        expected = b"correct horse battery staple"
        encrypt(cover, carrier, expected, "test-password")
        actual = decrypt(carrier, "test-password", None)
        assert actual == expected, "round-trip mismatch"

        try:
            decrypt(carrier, "wrong-password", None)
        except StegoError:
            pass
        else:
            raise AssertionError("wrong password was accepted")

        print("Self-test passed: round-trip OK, wrong password rejected.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Hide AES-GCM encrypted messages in PNG images (LSB steganography)."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    enc = subparsers.add_parser("encrypt", help="Embed an encrypted message in a PNG.")
    enc.add_argument("-i", "--input", required=True, type=Path, help="Cover PNG.")
    enc.add_argument("-o", "--output", required=True, type=Path, help="Output PNG.")
    enc.add_argument("-p", "--password", help="Password (prompted if omitted).")
    source = enc.add_mutually_exclusive_group(required=True)
    source.add_argument("-m", "--message", help="Message text.")
    source.add_argument("-f", "--message-file", type=Path, help="Read message from a file.")

    dec = subparsers.add_parser("decrypt", help="Extract and decrypt a message.")
    dec.add_argument("-i", "--input", required=True, type=Path, help="Carrier PNG.")
    dec.add_argument("-p", "--password", help="Password (prompted if omitted).")
    dec.add_argument("-o", "--output", type=Path, help="Write plaintext to this file.")

    subparsers.add_parser("selftest", help="Run an in-memory round-trip test.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "selftest":
            selftest()
            return 0

        password = _password(args.password)
        if args.command == "encrypt":
            message = (
                args.message.encode("utf-8")
                if args.message is not None
                else args.message_file.read_bytes()
            )
            encrypt(args.input, args.output, message, password)
            return 0

        message = decrypt(args.input, password, args.output)
        if args.output is None:
            sys.stdout.buffer.write(message)
            if not message.endswith(b"\n"):
                sys.stdout.buffer.write(b"\n")
        return 0
    except StegoError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
