# CryptoLens

An interactive web app that shows what encryption actually does to data. It has a Python (Flask) backend that performs real cryptography with the `cryptography` library, and a plain HTML/CSS/JavaScript frontend that draws every step. There is no build step and no database.

## How to run

You need **Python 3.9 or newer**. Check with `python --version` (or `python3 --version`).

**Easiest way**

- Windows: double-click `run.bat`
- Mac / Linux: open a terminal in this folder and run `./run.sh`

Then open **http://127.0.0.1:5050** in your browser.

**Manual way (same result)**

```bash
cd cryptolens
python -m venv .venv

# activate the virtual environment
#   Windows (PowerShell):  .venv\Scripts\Activate.ps1
#   Windows (cmd):         .venv\Scripts\activate.bat
#   Mac / Linux:           source .venv/bin/activate

pip install -r requirements.txt
python app.py
```

Stop the server with `Ctrl + C`. To use another port: `PORT=8000 python app.py` (Mac / Linux) or `set PORT=8000 && python app.py` (Windows cmd).

**Run the tests**

```bash
python -m unittest discover -s tests -v
```

## What it shows

| Tab | What you see | Idea behind it |
|---|---|---|
| Encrypt | AES-GCM, ChaCha20-Poly1305, AES-CBC, AES-ECB and RSA-OAEP, with the key, IV or nonce, every block, and the final ciphertext. A button flips one bit of the ciphertext and decrypts again. | Authenticated encryption (GCM, ChaCha20) detects tampering. CBC and ECB do not. |
| Avalanche | A heatmap of output bits before and after flipping one input bit (AES plaintext, AES key, or SHA-256), plus a histogram over every possible single-bit flip. | A good cipher or hash changes about 50% of the output for any 1-bit change. |
| Block modes | One picture encrypted with ECB, CBC and GCM, with a count of unique 16-byte blocks. You can upload your own image. | ECB encrypts equal blocks to equal ciphertext, so the picture's outline leaks. |
| Handshake | X25519 key exchange between Alice and Bob, with optional attacker (Mallory) and optional Ed25519 signatures. | Encryption alone does not prove who you are talking to. Signatures (authentication) stop the man-in-the-middle attack. |

## Project structure

```
cryptolens/
  app.py                 Flask backend: all cryptography and the JSON API
  requirements.txt       Flask, cryptography
  run.sh / run.bat       One-step launchers
  static/
    index.html           Page layout and the four tabs
    css/style.css        Styling (light and dark mode, mobile friendly)
    js/util.js           Shared helpers (DOM, API calls, byte cells)
    js/encrypt.js        Encrypt tab
    js/avalanche.js      Avalanche tab
    js/blocks.js         Block modes tab
    js/handshake.js      Handshake tab
    js/main.js           Tab switching
  tests/test_api.py      21 backend tests
```

## API reference

All endpoints take and return JSON.

| Method and path | Purpose |
|---|---|
| `POST /api/encrypt` | `{algo, plaintext, key_bits?, key_hex?}` returns key, IV/nonce, tag, per-block steps and ciphertext |
| `POST /api/decrypt` | `{algo, key_hex, iv_hex, tag_hex, ciphertext_hex, tamper_index?}` returns plaintext, or reports that tampering was detected |
| `POST /api/avalanche` | `{primitive, message, bit}` returns before/after bits, the difference, and a sweep over all bit flips |
| `POST /api/image-modes` | `{pixels_b64}` returns the picture encrypted with ECB, CBC and GCM, plus block statistics |
| `POST /api/handshake` | `{attacker, authenticated, message}` returns each protocol step and the outcome |
| `GET /api/health` | Status check |

## Security notes (include these in your report)

- This is a **teaching tool**. It deliberately shows keys and internal values, and it runs the RSA private key in server memory. Do not use it to protect real data.
- All primitives come from the well-reviewed `cryptography` library. The step-by-step views are rebuilt from the same primitives and checked against the library's output in the tests (for example, the CBC chain and the GCM keystream).
- Randomness comes from `os.urandom`. Keys, IVs and nonces are fresh for every request.
- ECB mode is included only to demonstrate its weakness.
- The server listens on `127.0.0.1` only, so other machines cannot reach it.
- Request size is limited (4 MB), text is limited to 2000 bytes and images to 512 x 512 pixels.

## Suggested report outline

1. **Problem statement and objectives**: why people need to see cryptography, not just read about it.
2. **Background**: symmetric vs public-key encryption, block modes, authenticated encryption, hashing, key exchange, man-in-the-middle attacks.
3. **System design**: architecture diagram (browser, Flask API, `cryptography` library) and a data flow for one encryption request.
4. **Implementation**: one subsection per tab, using the screenshots from the running app.
5. **Results**: avalanche average (about 50%), unique-block counts for ECB vs CBC/GCM, tamper detection table, MITM outcomes in all three configurations.
6. **Security analysis**: what each mode protects and what it does not; the limits listed above.
7. **Conclusion and future scope**: ideas such as ChaCha20 visualization at round level, TLS handshake view, post-quantum key exchange (ML-KEM), or password hashing demo.

## Likely viva questions

- **Why does ECB leak the picture?** It encrypts each 16-byte block independently with the same key, so equal blocks give equal ciphertext. Large flat areas become repeated blocks.
- **Why does CBC fix that, and what does it not fix?** Each block is XORed with the previous ciphertext block (or the IV) first, so equal plaintext blocks differ. It still gives no integrity check, and padding errors can leak information.
- **What does GCM add?** It turns AES into a stream cipher using a counter and adds a 16-byte authentication tag, so any change to the ciphertext is detected.
- **What happens if a GCM nonce repeats with the same key?** The same keystream is reused, so XORing two ciphertexts reveals the XOR of the plaintexts, and the authentication key can be recovered. Nonces must never repeat.
- **What is the avalanche effect and why does it matter?** A one-bit input change should flip about half of the output bits. If it did not, attackers could learn about the key or message from small differences.
- **Why can't RSA encrypt a long message?** RSA-OAEP with a 2048-bit key handles at most 190 bytes, and it is slow. Real systems use hybrid encryption: RSA or ECDH protects a short AES key, and AES encrypts the message.
- **Why does Diffie-Hellman not stop a man in the middle?** It gives both sides a shared secret but does not tell them who they share it with. Mallory can run one exchange with each side.
- **How do signatures stop it?** Each side signs its public key with a long-term identity key the other side already trusts. Mallory cannot forge a signature for her own key.
- **Why X25519 and Ed25519?** They are modern elliptic-curve algorithms: small keys, fast, and designed to avoid common implementation mistakes.
- **What is HKDF used for here?** The raw Diffie-Hellman output is not uniformly random. HKDF turns it into a proper 256-bit session key.
