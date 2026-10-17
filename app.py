"""CryptoLens backend.

A small Flask API that performs *real* cryptography (using the `cryptography`
library) and returns every intermediate value, so the frontend can show what
happens inside each algorithm instead of just printing a final ciphertext.

Run:  python app.py   ->  http://127.0.0.1:5050
"""

from __future__ import annotations

import base64
import hashlib
import math
import os
from collections import Counter
from functools import lru_cache

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, x25519
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from flask import Flask, jsonify, request, send_from_directory

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")

app = Flask(__name__, static_folder=STATIC_DIR, static_url_path="/static")
app.config["MAX_CONTENT_LENGTH"] = 4 * 1024 * 1024  # 4 MB request limit

BLOCK = 16
MAX_TEXT_BYTES = 2000
MAX_IMAGE_BYTES = 3 * 512 * 512

ALGORITHMS = {
    "aes-gcm": "AES-GCM",
    "aes-cbc": "AES-CBC",
    "aes-ecb": "AES-ECB",
    "chacha20": "ChaCha20-Poly1305",
    "rsa-oaep": "RSA-OAEP",
}


# --------------------------------------------------------------------------
# Plumbing
# --------------------------------------------------------------------------
class ApiError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.message = message
        self.status = status


@app.errorhandler(ApiError)
def handle_api_error(err: ApiError):
    return jsonify({"error": err.message}), err.status


@app.errorhandler(413)
def handle_too_large(_err):
    return jsonify({"error": "That request is too large. Try a smaller image or message."}), 413


@app.errorhandler(404)
def handle_not_found(_err):
    return jsonify({"error": "Not found."}), 404


def body_json() -> dict:
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise ApiError("Send a JSON object in the request body.")
    return data


def get_hex(data: dict, name: str, lengths: tuple[int, ...] | None = None, required: bool = True):
    value = data.get(name)
    if value in (None, ""):
        if required:
            raise ApiError(f"Missing field: {name}.")
        return None
    try:
        raw = bytes.fromhex(value)
    except (ValueError, TypeError):
        raise ApiError(f"{name} must be a hexadecimal string.") from None
    if lengths and len(raw) not in lengths:
        allowed = ", ".join(str(n) for n in lengths)
        raise ApiError(f"{name} must be {allowed} bytes long.")
    return raw


def chunks(data: bytes, size: int = BLOCK) -> list[bytes]:
    return [data[i : i + size] for i in range(0, len(data), size)]


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def popcount(data: bytes) -> int:
    return bin(int.from_bytes(data, "big")).count("1")


def bits_of(data: bytes) -> list[int]:
    return [(byte >> (7 - i)) & 1 for byte in data for i in range(8)]


def flip_bit(data: bytes, bit: int) -> bytes:
    out = bytearray(data)
    out[bit // 8] ^= 0x80 >> (bit % 8)
    return bytes(out)


def aes_block(key: bytes, block: bytes) -> bytes:
    """Raw AES on a single 16-byte block (no mode, no padding)."""
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(block) + enc.finalize()


def text_from(data: dict) -> bytes:
    text = data.get("plaintext")
    if not isinstance(text, str) or text == "":
        raise ApiError("Enter some text to encrypt.")
    raw = text.encode("utf-8")
    if len(raw) > MAX_TEXT_BYTES:
        raise ApiError(f"Keep the message under {MAX_TEXT_BYTES} bytes.")
    return raw


def pick_symmetric_key(data: dict, algo: str) -> bytes:
    supplied = get_hex(data, "key_hex", required=False)
    if algo == "chacha20":
        if supplied is not None and len(supplied) != 32:
            raise ApiError("ChaCha20-Poly1305 needs a 32-byte (64 hex characters) key.")
        return supplied or os.urandom(32)
    if supplied is not None:
        if len(supplied) not in (16, 24, 32):
            raise ApiError("An AES key must be 16, 24 or 32 bytes (32, 48 or 64 hex characters).")
        return supplied
    bits = data.get("key_bits", 256)
    if bits not in (128, 192, 256):
        raise ApiError("key_bits must be 128, 192 or 256.")
    return os.urandom(bits // 8)


# --------------------------------------------------------------------------
# Pages
# --------------------------------------------------------------------------
@app.get("/")
def index():
    return send_from_directory(STATIC_DIR, "index.html")


@app.get("/api/health")
def health():
    return jsonify({"status": "ok", "algorithms": ALGORITHMS})


# --------------------------------------------------------------------------
# 1. Encryption lab
# --------------------------------------------------------------------------
@lru_cache(maxsize=1)
def rsa_private_key():
    # Generated once per server process, kept only in memory.
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def oaep():
    return asym_padding.OAEP(mgf=asym_padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


def encrypt_block_mode(algo: str, key: bytes, plaintext: bytes) -> dict:
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    pad_len = padded[-1]
    iv = os.urandom(16) if algo == "aes-cbc" else None

    # Authoritative ciphertext from the library's own mode implementation...
    mode = modes.CBC(iv) if algo == "aes-cbc" else modes.ECB()
    enc = Cipher(algorithms.AES(key), mode).encryptor()
    ciphertext = enc.update(padded) + enc.finalize()

    # ...and the same result rebuilt block by block, so the UI can show the chaining.
    steps, previous = [], iv
    blocks = chunks(padded)
    for i, blk in enumerate(blocks):
        mixed = xor_bytes(blk, previous) if algo == "aes-cbc" else blk
        out = aes_block(key, mixed)
        steps.append(
            {
                "index": i,
                "plaintext_hex": blk.hex(),
                "xor_with_hex": previous.hex() if algo == "aes-cbc" else None,
                "input_hex": mixed.hex(),
                "ciphertext_hex": out.hex(),
                "pad_bytes": pad_len if i == len(blocks) - 1 else 0,
            }
        )
        previous = out

    return {
        "iv_hex": iv.hex() if iv else "",
        "iv_label": "IV",
        "padded_hex": padded.hex(),
        "ciphertext_hex": ciphertext.hex(),
        "tag_hex": "",
        "blocks": steps,
        "notes": (
            [
                "Each plaintext block is XORed with the previous ciphertext block (the IV for block 0) before AES runs.",
                "There is no integrity check: changing a ciphertext byte garbles data but is not reported.",
            ]
            if algo == "aes-cbc"
            else [
                "Every block is encrypted on its own with the same key. Identical plaintext blocks give identical ciphertext blocks.",
                "ECB leaks patterns and has no integrity check. It is here to show why it should not be used.",
            ]
        ),
    }


def encrypt_gcm(key: bytes, plaintext: bytes) -> dict:
    nonce = os.urandom(12)
    sealed = AESGCM(key).encrypt(nonce, plaintext, None)
    ciphertext, tag = sealed[:-16], sealed[-16:]
    steps = []
    for i, (pblk, cblk) in enumerate(zip(chunks(plaintext), chunks(ciphertext))):
        counter = nonce + (i + 2).to_bytes(4, "big")  # counter 1 is reserved for the tag
        keystream = aes_block(key, counter)[: len(pblk)]
        steps.append(
            {
                "index": i,
                "plaintext_hex": pblk.hex(),
                "counter_hex": counter.hex(),
                "keystream_hex": keystream.hex(),
                "ciphertext_hex": cblk.hex(),
            }
        )
    return {
        "iv_hex": nonce.hex(),
        "iv_label": "Nonce",
        "padded_hex": "",
        "ciphertext_hex": ciphertext.hex(),
        "tag_hex": tag.hex(),
        "blocks": steps,
        "notes": [
            "AES encrypts a counter (nonce + block number) to make a keystream, which is XORed with the plaintext.",
            "The 16-byte tag authenticates the ciphertext: any change is caught before decryption.",
            "Never reuse a nonce with the same key.",
        ],
    }


def encrypt_chacha(key: bytes, plaintext: bytes) -> dict:
    nonce = os.urandom(12)
    sealed = ChaCha20Poly1305(key).encrypt(nonce, plaintext, None)
    ciphertext, tag = sealed[:-16], sealed[-16:]
    steps = []
    for i, (pblk, cblk) in enumerate(zip(chunks(plaintext), chunks(ciphertext))):
        steps.append(
            {
                "index": i,
                "plaintext_hex": pblk.hex(),
                "keystream_hex": xor_bytes(pblk, cblk).hex(),
                "ciphertext_hex": cblk.hex(),
            }
        )
    return {
        "iv_hex": nonce.hex(),
        "iv_label": "Nonce",
        "padded_hex": "",
        "ciphertext_hex": ciphertext.hex(),
        "tag_hex": tag.hex(),
        "blocks": steps,
        "notes": [
            "ChaCha20 turns the key and nonce into a keystream with add, rotate and XOR operations, then XORs it with the plaintext.",
            "Poly1305 produces the authentication tag. This design is fast on devices without AES hardware.",
        ],
    }


def encrypt_rsa(plaintext: bytes) -> dict:
    if len(plaintext) > 190:
        raise ApiError(
            "RSA-OAEP with a 2048-bit key encrypts at most 190 bytes. "
            "Real systems use RSA to protect a short AES key and AES for the message (hybrid encryption)."
        )
    public = rsa_private_key().public_key()
    numbers = public.public_numbers()
    ciphertext = public.encrypt(plaintext, oaep())
    return {
        "key_hex": format(numbers.n, "x"),
        "key_bits": numbers.n.bit_length(),
        "exponent": numbers.e,
        "iv_hex": "",
        "iv_label": "",
        "padded_hex": "",
        "ciphertext_hex": ciphertext.hex(),
        "tag_hex": "",
        "blocks": [
            {
                "index": 0,
                "plaintext_hex": plaintext.hex(),
                "ciphertext_hex": ciphertext.hex(),
            }
        ],
        "notes": [
            "The message is padded with OAEP (random, so the same text encrypts differently each time), then raised to the power e modulo n.",
            "Only the private key, which stays on the server, can reverse it.",
        ],
    }


@app.post("/api/encrypt")
def encrypt():
    data = body_json()
    algo = data.get("algo")
    if algo not in ALGORITHMS:
        raise ApiError("Unknown algorithm. Choose one of: " + ", ".join(ALGORITHMS))
    plaintext = text_from(data)

    if algo == "rsa-oaep":
        result = encrypt_rsa(plaintext)
    else:
        key = pick_symmetric_key(data, algo)
        if algo == "aes-gcm":
            result = encrypt_gcm(key, plaintext)
        elif algo == "chacha20":
            result = encrypt_chacha(key, plaintext)
        else:
            result = encrypt_block_mode(algo, key, plaintext)
        result["key_hex"] = key.hex()
        result["key_bits"] = len(key) * 8

    result.update({"algo": algo, "label": ALGORITHMS[algo], "plaintext_hex": plaintext.hex()})
    return jsonify(result)


def readable(raw: bytes) -> str:
    return raw.decode("utf-8", errors="replace")


@app.post("/api/decrypt")
def decrypt():
    data = body_json()
    algo = data.get("algo")
    if algo not in ALGORITHMS:
        raise ApiError("Unknown algorithm.")
    ciphertext = get_hex(data, "ciphertext_hex")

    tampered = False
    tamper_index = data.get("tamper_index")
    if tamper_index is not None:
        if not isinstance(tamper_index, int) or not 0 <= tamper_index < len(ciphertext):
            raise ApiError("tamper_index is outside the ciphertext.")
        # Flip a single bit: the smallest change an attacker could make.
        ciphertext = ciphertext[:tamper_index] + bytes([ciphertext[tamper_index] ^ 0x01]) + ciphertext[tamper_index + 1 :]
        tampered = True

    reply = {"tampered": tampered, "ok": False, "detected": False, "plaintext": "", "plaintext_hex": "", "message": ""}

    if algo == "rsa-oaep":
        try:
            raw = rsa_private_key().decrypt(ciphertext, oaep())
        except ValueError:
            reply.update(detected=True, message="OAEP check failed: the ciphertext was altered, so nothing was decrypted.")
            return jsonify(reply)
        reply.update(ok=True, plaintext=readable(raw), plaintext_hex=raw.hex(), message="Decrypted with the private key.")
        return jsonify(reply)

    key = get_hex(data, "key_hex", lengths=(16, 24, 32))
    iv = get_hex(data, "iv_hex", required=algo in ("aes-gcm", "aes-cbc", "chacha20"))

    if algo in ("aes-gcm", "chacha20"):
        tag = get_hex(data, "tag_hex", lengths=(16,))
        aead = AESGCM(key) if algo == "aes-gcm" else ChaCha20Poly1305(key)
        try:
            raw = aead.decrypt(iv, ciphertext + tag, None)
        except InvalidTag:
            reply.update(
                detected=True,
                message="Authentication tag mismatch: the ciphertext was modified, so decryption was refused.",
            )
            return jsonify(reply)
        reply.update(ok=True, plaintext=readable(raw), plaintext_hex=raw.hex(), message="Tag verified. Message is authentic.")
        return jsonify(reply)

    # AES-CBC / AES-ECB: decrypt first, then try to remove the padding.
    if len(ciphertext) % BLOCK:
        raise ApiError("Ciphertext length must be a multiple of 16 bytes.")
    mode = modes.CBC(iv) if algo == "aes-cbc" else modes.ECB()
    dec = Cipher(algorithms.AES(key), mode).decryptor()
    raw = dec.update(ciphertext) + dec.finalize()
    try:
        unpadder = padding.PKCS7(128).unpadder()
        raw = unpadder.update(raw) + unpadder.finalize()
        padding_ok = True
    except ValueError:
        padding_ok = False
    if padding_ok:
        message = (
            "Decrypted with no error, but the text is garbled. Nothing warned you that the data was changed."
            if tampered
            else "Decrypted. This mode has no way to tell whether the data was changed."
        )
    else:
        message = "Padding is invalid after the change. This is a side effect, not real tamper detection."
    reply.update(ok=padding_ok, plaintext=readable(raw), plaintext_hex=raw.hex(), message=message)
    return jsonify(reply)


# --------------------------------------------------------------------------
# 2. Avalanche effect
# --------------------------------------------------------------------------
DEMO_KEY = hashlib.sha256(b"cryptolens avalanche demo").digest()[:16]


def avalanche_setup(primitive: str, message: str):
    raw = message.encode("utf-8")
    if primitive == "aes-plaintext":
        block = raw[:16].ljust(16, b"\x00")
        return block, lambda value: aes_block(DEMO_KEY, value), "AES-128 block, flip a plaintext bit"
    if primitive == "aes-key":
        block = raw[:16].ljust(16, b"\x00")
        return DEMO_KEY, lambda value: aes_block(value, block), "AES-128 block, flip a key bit"
    if primitive == "sha256":
        if not raw:
            raise ApiError("Enter a message to hash.")
        raw = raw[:64]
        return raw, lambda value: hashlib.sha256(value).digest(), "SHA-256, flip a message bit"
    raise ApiError("primitive must be aes-plaintext, aes-key or sha256.")


@app.post("/api/avalanche")
def avalanche():
    data = body_json()
    primitive = data.get("primitive", "aes-plaintext")
    message = data.get("message", "")
    if not isinstance(message, str):
        raise ApiError("message must be text.")
    base, fn, label = avalanche_setup(primitive, message)

    input_bits = len(base) * 8
    try:
        bit = int(data.get("bit", 0))
    except (TypeError, ValueError):
        raise ApiError("bit must be a number.") from None
    bit = max(0, min(bit, input_bits - 1))

    original = fn(base)
    flipped_input = flip_bit(base, bit)
    flipped = fn(flipped_input)
    diff = xor_bytes(original, flipped)
    output_bits = len(original) * 8

    sweep = [popcount(xor_bytes(original, fn(flip_bit(base, i)))) for i in range(input_bits)]

    return jsonify(
        {
            "primitive": primitive,
            "label": label,
            "input_bits": input_bits,
            "output_bits": output_bits,
            "bit": bit,
            "input_hex": base.hex(),
            "flipped_input_hex": flipped_input.hex(),
            "output_hex": original.hex(),
            "flipped_output_hex": flipped.hex(),
            "original_bits": bits_of(original),
            "flipped_bits": bits_of(flipped),
            "diff_bits": bits_of(diff),
            "changed": popcount(diff),
            "percent": round(100 * popcount(diff) / output_bits, 1),
            "sweep": sweep,
            "sweep_mean": round(sum(sweep) / len(sweep), 2),
        }
    )


# --------------------------------------------------------------------------
# 3. ECB vs CBC vs GCM on an image
# --------------------------------------------------------------------------
def byte_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    total = len(data)
    return -sum((n / total) * math.log2(n / total) for n in Counter(data).values())


def block_stats(data: bytes) -> dict:
    blocks = chunks(data)
    return {
        "total_blocks": len(blocks),
        "unique_blocks": len(set(blocks)),
        "entropy": round(byte_entropy(data), 3),
    }


@app.post("/api/image-modes")
def image_modes():
    data = body_json()
    try:
        raw = base64.b64decode(data.get("pixels_b64", ""), validate=True)
    except (ValueError, TypeError):
        raise ApiError("pixels_b64 must be base64 encoded pixel data.") from None
    if not raw:
        raise ApiError("No pixel data received.")
    if len(raw) > MAX_IMAGE_BYTES:
        raise ApiError("Image is too large. Use at most 512 x 512 pixels.")

    key, iv, nonce = os.urandom(16), os.urandom(16), os.urandom(12)
    padded = raw + b"\x00" * (-len(raw) % BLOCK)  # only so the block ciphers can run; trimmed again below

    ecb = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    ecb_out = (ecb.update(padded) + ecb.finalize())[: len(raw)]
    cbc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    cbc_out = (cbc.update(padded) + cbc.finalize())[: len(raw)]
    gcm_out = AESGCM(key).encrypt(nonce, raw, None)[: len(raw)]

    def pack(blob: bytes) -> dict:
        return {"b64": base64.b64encode(blob).decode("ascii"), **block_stats(blob)}

    return jsonify(
        {
            "original": block_stats(raw),
            "ecb": pack(ecb_out),
            "cbc": pack(cbc_out),
            "gcm": pack(gcm_out),
        }
    )


# --------------------------------------------------------------------------
# 4. Key exchange and man-in-the-middle
# --------------------------------------------------------------------------
def raw_public(key) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def fingerprint(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()[:16]


def session_key(private: x25519.X25519PrivateKey, peer_public: bytes, label: bytes) -> bytes:
    shared = private.exchange(x25519.X25519PublicKey.from_public_bytes(peer_public))
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"cryptolens " + label).derive(shared)


def signature_valid(identity_public: bytes, signature: bytes, signed: bytes) -> bool:
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(identity_public).verify(signature, signed)
        return True
    except InvalidSignature:
        return False


@app.post("/api/handshake")
def handshake():
    data = body_json()
    attacker = bool(data.get("attacker"))
    authenticated = bool(data.get("authenticated"))
    message = str(data.get("message") or "Meet at the library at 5 pm.")[:200]
    plaintext = message.encode("utf-8")

    # Ephemeral Diffie-Hellman keys for the three parties.
    alice, bob = x25519.X25519PrivateKey.generate(), x25519.X25519PrivateKey.generate()
    mal_to_alice, mal_to_bob = x25519.X25519PrivateKey.generate(), x25519.X25519PrivateKey.generate()
    alice_pub, bob_pub = raw_public(alice), raw_public(bob)
    mal_to_alice_pub, mal_to_bob_pub = raw_public(mal_to_alice), raw_public(mal_to_bob)

    # Long-term identity keys, pinned in advance by the other side (like a verified fingerprint).
    alice_id, bob_id, mal_id = (ed25519.Ed25519PrivateKey.generate() for _ in range(3))
    alice_id_pub, bob_id_pub = raw_public(alice_id), raw_public(bob_id)

    steps: list[dict] = []

    def add(sender, receiver, kind, title, detail, values=None, ok=None):
        steps.append(
            {
                "n": len(steps) + 1,
                "from": sender,
                "to": receiver,
                "kind": kind,
                "title": title,
                "detail": detail,
                "values": values or [],
                "ok": ok,
            }
        )

    def val(label, raw):
        return {"label": label, "hex": raw.hex()}

    outcome = {"detected": False, "mallory_read": None, "bob_received": None, "same_key": None}
    route = "mallory" if attacker else "bob"

    # ---- Step: Alice -> Bob (through Mallory if she is on the path) ----------------------
    alice_sig = alice_id.sign(alice_pub) if authenticated else b""
    values = [val("Alice's public key", alice_pub)]
    if authenticated:
        values.append(val("Signature by Alice's identity key", alice_sig))
    add("alice", route, "key", "Alice sends her public key",
        "A fresh key for this conversation" + (", signed with her long-term identity key." if authenticated else "."), values)

    if not attacker:
        if authenticated:
            ok = signature_valid(alice_id_pub, alice_sig, alice_pub)
            add("bob", "bob", "check", "Bob checks Alice's signature", "The signature matches the identity key Bob already trusts.", ok=ok)
        add("bob", "alice", "key", "Bob replies with his public key",
            "Signed with his identity key." if authenticated else "Same idea, in the other direction.",
            [val("Bob's public key", bob_pub)] + ([val("Signature by Bob's identity key", bob_id.sign(bob_pub))] if authenticated else []))
        if authenticated:
            ok = signature_valid(bob_id_pub, bob_id.sign(bob_pub), bob_pub)
            add("alice", "alice", "check", "Alice checks Bob's signature", "The signature matches the identity key Alice already trusts.", ok=ok)

        key_a = session_key(alice, bob_pub, b"session")
        key_b = session_key(bob, alice_pub, b"session")
        same = key_a == key_b
        add("alice", "bob", "check", "Both sides derive the same secret key",
            "Each side combines its private key with the other's public key. The secret itself never crosses the network.",
            [val("Alice's session key fingerprint", hashlib.sha256(key_a).digest()[:8]),
             val("Bob's session key fingerprint", hashlib.sha256(key_b).digest()[:8])], ok=same)

        nonce = os.urandom(12)
        sealed = AESGCM(key_a).encrypt(nonce, plaintext, None)
        add("alice", "bob", "cipher", "Alice sends an encrypted message",
            "Anyone watching the network sees only this ciphertext.", [val("Ciphertext + tag", sealed)])
        received = AESGCM(key_b).decrypt(nonce, sealed, None)
        add("bob", "bob", "check", "Bob decrypts it", "Bob reads the original message.", [val("Plaintext", received)], ok=True)
        outcome.update(bob_received=received.decode("utf-8"), same_key=same, mallory_read=None)
        outcome["verdict"] = "Secure. A passive eavesdropper sees only ciphertext."
        return jsonify({"steps": steps, "outcome": outcome, "attacker": attacker, "authenticated": authenticated,
                        "fingerprints": {"alice": fingerprint(alice_id_pub), "bob": fingerprint(bob_id_pub)} if authenticated else {}})

    # ---- Active attacker on the path ------------------------------------------------------
    if authenticated:
        # Attempt 1: forward Alice's real signature next to Mallory's substituted key.
        ok1 = signature_valid(alice_id_pub, alice_sig, mal_to_bob_pub)
        add("mallory", "bob", "key", "Mallory swaps in her own key",
            "She keeps Alice's original signature, but it was made for Alice's key, not for this one.",
            [val("Mallory's key (pretending to be Alice)", mal_to_bob_pub), val("Alice's signature, reused", alice_sig)])
        add("bob", "bob", "check", "Bob checks the signature", "The signature does not match the swapped key.", ok=ok1)
        # Attempt 2: sign the substituted key with Mallory's own identity key.
        forged = mal_id.sign(mal_to_bob_pub)
        ok2 = signature_valid(alice_id_pub, forged, mal_to_bob_pub)
        add("mallory", "bob", "key", "Mallory signs the swapped key herself",
            "She has no access to Alice's identity key, so she uses her own.", [val("Forged signature", forged)])
        add("bob", "bob", "alert", "Bob rejects the handshake",
            "The signature is not from the identity key Bob trusts for Alice. The connection is closed before any message is sent.", ok=ok2)
        outcome.update(detected=True, mallory_read=None, bob_received=None)
        outcome["verdict"] = "Attack detected. Signatures stop the key swap, so Mallory learns nothing."
        return jsonify({"steps": steps, "outcome": outcome, "attacker": attacker, "authenticated": authenticated,
                        "fingerprints": {"alice": fingerprint(alice_id_pub), "bob": fingerprint(bob_id_pub)}})

    # Unauthenticated: Mallory completes two separate handshakes.
    add("mallory", "bob", "key", "Mallory swaps in her own key for Alice's",
        "Nothing proves whose key this is, so Bob accepts it.", [val("Mallory's key (pretending to be Alice)", mal_to_bob_pub)])
    add("bob", "mallory", "key", "Bob replies with his public key", "Mallory intercepts it.", [val("Bob's public key", bob_pub)])
    add("mallory", "alice", "key", "Mallory swaps in her own key for Bob's",
        "Alice believes this key belongs to Bob.", [val("Mallory's key (pretending to be Bob)", mal_to_alice_pub)])

    k_alice = session_key(alice, mal_to_alice_pub, b"session")
    k_mal_alice = session_key(mal_to_alice, alice_pub, b"session")
    k_bob = session_key(bob, mal_to_bob_pub, b"session")
    k_mal_bob = session_key(mal_to_bob, bob_pub, b"session")
    add("mallory", "mallory", "check", "Two separate secret keys now exist",
        "Alice shares one with Mallory, and Bob shares a different one with Mallory. Alice and Bob do not share any.",
        [val("Alice and Mallory", hashlib.sha256(k_alice).digest()[:8]), val("Bob and Mallory", hashlib.sha256(k_bob).digest()[:8])],
        ok=(k_alice == k_mal_alice and k_bob == k_mal_bob))

    nonce1 = os.urandom(12)
    sealed1 = AESGCM(k_alice).encrypt(nonce1, plaintext, None)
    add("alice", "mallory", "cipher", "Alice sends an encrypted message",
        "She thinks only Bob can read it.", [val("Ciphertext + tag", sealed1)])
    stolen = AESGCM(k_mal_alice).decrypt(nonce1, sealed1, None)
    add("mallory", "mallory", "alert", "Mallory decrypts and reads it", "She can also change it before passing it on.", [val("Plaintext", stolen)], ok=False)
    nonce2 = os.urandom(12)
    sealed2 = AESGCM(k_mal_bob).encrypt(nonce2, stolen, None)
    add("mallory", "bob", "cipher", "Mallory re-encrypts it for Bob", "Bob sees a valid message and suspects nothing.", [val("Ciphertext + tag", sealed2)])
    received = AESGCM(k_bob).decrypt(nonce2, sealed2, None)
    add("bob", "bob", "check", "Bob decrypts it", "It looks normal to Bob.", [val("Plaintext", received)], ok=True)

    outcome.update(mallory_read=stolen.decode("utf-8"), bob_received=received.decode("utf-8"), detected=False)
    outcome["verdict"] = "Attack succeeded. Encryption alone does not prove who you are talking to."
    return jsonify({"steps": steps, "outcome": outcome, "attacker": attacker, "authenticated": authenticated, "fingerprints": {}})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5050"))
    print(f"CryptoLens running at http://127.0.0.1:{port}")
    app.run(host="127.0.0.1", port=port, debug=False)
