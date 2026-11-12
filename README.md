# Image Steganography

Hide an **AES-GCM encrypted** message inside a PNG and recover it with the right password. The encrypted bytes are written into the least-significant bit of each RGB channel, so the image looks unchanged to the eye.

A wrong password, a modified image, or a re-encoded (JPEG/WebP) image fails cleanly instead of returning garbage.

## Features

- **AES-256-GCM** authenticated encryption — confidentiality *and* tamper detection.
- **PBKDF2-HMAC-SHA256** key derivation, 600,000 iterations, random 16-byte salt per message.
- **Random 12-byte nonce** per message; never reused.
- **Header-bound authentication** — the magic, salt and nonce are used as AES-GCM associated data, so editing the header is detected.
- **Lossless PNG only** — the tool refuses JPEG/WebP output because compression destroys the hidden bits.
- **Clear failure modes** — distinct errors for "no message", "wrong password", and "corrupted image".
- **No network calls**, no metadata, no hidden state. Two dependencies.

## Install

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate

pip install -r requirements.txt
```

Requires Python 3.10+.

## Usage

### Encrypt

```bash
python stego.py encrypt -i cover.png -o carrier.png -p "correct horse battery staple" -m "meet me at the library"
```

Or read the message from a file:

```bash
python stego.py encrypt -i cover.png -o carrier.png -p "correct horse battery staple" -f message.txt
```

`cover.png` can be any RGB PNG. `carrier.png` is a new PNG that looks the same but carries the payload. Keep it as a PNG — screenshotting, resizing, or re-saving it as JPEG destroys the message.

### Decrypt

```bash
python stego.py decrypt -i carrier.png -p "correct horse battery staple"
```

Write the plaintext to a file instead of stdout:

```bash
python stego.py decrypt -i carrier.png -p "correct horse battery staple" -o message.txt
```

If `-p` is omitted, the password is prompted for without echoing it.

### Self-test

```bash
python stego.py selftest
```

Generates an image in memory, performs an encrypt/decrypt round-trip, and asserts that a wrong password is rejected.

## How it works

A fixed 36-byte header is embedded first, followed by the AES-GCM ciphertext:

| Field | Size | Purpose |
|---|---:|---|
| Magic | 4 bytes | `STG1`; lets the decoder reject unrelated images |
| Salt | 16 bytes | PBKDF2 salt, random per message |
| Nonce | 12 bytes | AES-GCM nonce, random per message |
| Length | 4 bytes | Ciphertext length, big-endian `uint32` |
| Ciphertext | *n* bytes | AES-GCM output, including the 16-byte tag |

Each payload bit replaces the least-significant bit of consecutive R, G and B channels, in row-major order. The decoder reads the header, derives the same key from the password and salt, then verifies and decrypts the ciphertext. Because the magic, salt and nonce are passed as associated data, a modified header causes authentication to fail.

## Capacity

```
capacity_bytes = (width × height × 3) // 8
usable_bytes   = capacity_bytes - 36
```

A 1920×1080 image holds about **777 KB** of ciphertext (roughly 759 KB of plaintext). The tool checks capacity before writing and reports the limit if the message does not fit.

## Security notes

- **LSB steganography is fragile, not robust.** Any lossy re-encode, resize, crop, or colour adjustment destroys the payload. Always keep and transmit the output as a PNG.
- **This is not undetectable.** LSB embedding changes the image's statistical profile; steganalysis tools can often flag it. Use it for learning and puzzles, not for hiding data from a determined examiner.
- **The password is the only secret.** Use a long, unique passphrase. PBKDF2 slows guessing but cannot rescue a weak password.
- **The image dimensions, file size and the fact that *something* is embedded are not hidden.** Only the message content is encrypted.
- **Do not reuse `carrier.png` across messages.** Each run creates a fresh salt and nonce; reusing an output as a cover is fine only if you accept overwriting the old payload.

## Project structure

```
stego.py          CLI: encrypt, decrypt, selftest
requirements.txt  cryptography, pillow
LICENSE           MIT
```

## License

MIT © 2026 Yash Chauhan
