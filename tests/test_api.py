"""Backend tests. Run from the project folder with:  python -m unittest discover -s tests -v"""

import base64
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # noqa: E402

from app import app  # noqa: E402


class CryptoLensTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def post(self, path, payload):
        return self.client.post(path, json=payload)

    # ---- encryption lab -------------------------------------------------
    def encrypt(self, algo, text="Attack at dawn! Bring the blue folder.", **extra):
        res = self.post("/api/encrypt", {"algo": algo, "plaintext": text, **extra})
        self.assertEqual(res.status_code, 200, res.get_json())
        return res.get_json()

    def decrypt(self, enc, **extra):
        payload = {
            "algo": enc["algo"],
            "key_hex": enc["key_hex"],
            "iv_hex": enc["iv_hex"],
            "ciphertext_hex": enc["ciphertext_hex"],
            "tag_hex": enc["tag_hex"],
            **extra,
        }
        if enc["algo"] == "rsa-oaep":
            payload.pop("key_hex")
        res = self.post("/api/decrypt", payload)
        self.assertEqual(res.status_code, 200, res.get_json())
        return res.get_json()

    def test_round_trip_all_algorithms(self):
        text = "Attack at dawn! Bring the blue folder."
        for algo in ("aes-gcm", "aes-cbc", "aes-ecb", "chacha20", "rsa-oaep"):
            with self.subTest(algo=algo):
                out = self.decrypt(self.encrypt(algo, text))
                self.assertTrue(out["ok"])
                self.assertEqual(out["plaintext"], text)

    def test_unicode_round_trip(self):
        text = "नमस्ते 🔐 Crypto"
        out = self.decrypt(self.encrypt("aes-gcm", text))
        self.assertEqual(out["plaintext"], text)

    def test_cbc_chain_matches_library_ciphertext(self):
        enc = self.encrypt("aes-cbc")
        rebuilt = "".join(b["ciphertext_hex"] for b in enc["blocks"])
        self.assertEqual(rebuilt, enc["ciphertext_hex"])
        for prev, cur in zip(enc["blocks"], enc["blocks"][1:]):
            self.assertEqual(cur["xor_with_hex"], prev["ciphertext_hex"])
        self.assertEqual(enc["blocks"][0]["xor_with_hex"], enc["iv_hex"])

    def test_ecb_blocks_match_library_ciphertext(self):
        enc = self.encrypt("aes-ecb")
        self.assertEqual("".join(b["ciphertext_hex"] for b in enc["blocks"]), enc["ciphertext_hex"])

    def test_ecb_repeats_identical_blocks(self):
        enc = self.encrypt("aes-ecb", "A" * 48)
        cts = [b["ciphertext_hex"] for b in enc["blocks"][:3]]
        self.assertEqual(len(set(cts)), 1)

    def test_cbc_hides_identical_blocks(self):
        enc = self.encrypt("aes-cbc", "A" * 48)
        cts = [b["ciphertext_hex"] for b in enc["blocks"][:3]]
        self.assertEqual(len(set(cts)), 3)

    def test_gcm_keystream_matches_ciphertext(self):
        enc = self.encrypt("aes-gcm", "x" * 40)
        for blk in enc["blocks"]:
            p, k, c = (bytes.fromhex(blk[f]) for f in ("plaintext_hex", "keystream_hex", "ciphertext_hex"))
            self.assertEqual(bytes(a ^ b for a, b in zip(p, k)), c)

    def test_aead_detects_tampering(self):
        for algo in ("aes-gcm", "chacha20"):
            with self.subTest(algo=algo):
                out = self.decrypt(self.encrypt(algo), tamper_index=0)
                self.assertFalse(out["ok"])
                self.assertTrue(out["detected"])
                self.assertEqual(out["plaintext"], "")

    def test_cbc_and_ecb_do_not_detect_tampering(self):
        for algo in ("aes-cbc", "aes-ecb"):
            with self.subTest(algo=algo):
                out = self.decrypt(self.encrypt(algo), tamper_index=0)
                self.assertFalse(out["detected"])
                self.assertNotEqual(out["plaintext_hex"], "")

    def test_rsa_rejects_long_messages_and_tampering(self):
        res = self.post("/api/encrypt", {"algo": "rsa-oaep", "plaintext": "a" * 200})
        self.assertEqual(res.status_code, 400)
        out = self.decrypt(self.encrypt("rsa-oaep"), tamper_index=3)
        self.assertTrue(out["detected"])

    def test_supplied_key_is_used(self):
        key = "00" * 32
        self.assertEqual(self.encrypt("aes-gcm", key_hex=key)["key_hex"], key)

    def test_key_size_option(self):
        self.assertEqual(self.encrypt("aes-cbc", key_bits=128)["key_bits"], 128)
        self.assertEqual(self.encrypt("aes-cbc", key_bits=192)["key_bits"], 192)

    def test_input_validation(self):
        bad = [
            {"algo": "des", "plaintext": "hi"},
            {"algo": "aes-gcm", "plaintext": ""},
            {"algo": "aes-gcm", "plaintext": "hi", "key_hex": "zz"},
            {"algo": "aes-gcm", "plaintext": "hi", "key_hex": "00" * 5},
            {"algo": "chacha20", "plaintext": "hi", "key_hex": "00" * 16},
            {"algo": "aes-gcm", "plaintext": "hi", "key_bits": 100},
            {"algo": "aes-gcm", "plaintext": "a" * 5000},
        ]
        for payload in bad:
            with self.subTest(payload=payload):
                res = self.post("/api/encrypt", payload)
                self.assertEqual(res.status_code, 400)
                self.assertIn("error", res.get_json())
        self.assertEqual(self.client.post("/api/encrypt", data="not json").status_code, 400)

    # ---- avalanche ------------------------------------------------------
    def test_avalanche_is_near_half(self):
        for primitive, message in (("aes-plaintext", "hello"), ("aes-key", "hello"), ("sha256", "hello world")):
            with self.subTest(primitive=primitive):
                res = self.post("/api/avalanche", {"primitive": primitive, "message": message, "bit": 3})
                self.assertEqual(res.status_code, 200)
                data = res.get_json()
                self.assertEqual(len(data["diff_bits"]), data["output_bits"])
                self.assertEqual(sum(data["diff_bits"]), data["changed"])
                self.assertEqual(len(data["sweep"]), data["input_bits"])
                self.assertAlmostEqual(data["sweep_mean"] / data["output_bits"], 0.5, delta=0.08)

    def test_avalanche_clamps_bit_and_validates(self):
        data = self.post("/api/avalanche", {"primitive": "aes-plaintext", "message": "x", "bit": 99999}).get_json()
        self.assertEqual(data["bit"], 127)
        self.assertEqual(self.post("/api/avalanche", {"primitive": "sha256", "message": ""}).status_code, 400)
        self.assertEqual(self.post("/api/avalanche", {"primitive": "md5", "message": "x"}).status_code, 400)

    # ---- image modes ----------------------------------------------------
    def test_image_modes_ecb_keeps_structure(self):
        pixels = bytes([255, 0, 0] * 400 + [0, 0, 255] * 400)  # two flat colour areas
        res = self.post("/api/image-modes", {"pixels_b64": base64.b64encode(pixels).decode()})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        for mode in ("ecb", "cbc", "gcm"):
            self.assertEqual(len(base64.b64decode(data[mode]["b64"])), len(pixels))
        self.assertLess(data["ecb"]["unique_blocks"], 10)
        self.assertGreater(data["cbc"]["unique_blocks"], data["cbc"]["total_blocks"] * 0.95)
        self.assertGreater(data["gcm"]["unique_blocks"], data["gcm"]["total_blocks"] * 0.95)

    def test_image_modes_validation(self):
        self.assertEqual(self.post("/api/image-modes", {"pixels_b64": "!!!"}).status_code, 400)
        self.assertEqual(self.post("/api/image-modes", {"pixels_b64": ""}).status_code, 400)

    # ---- handshake ------------------------------------------------------
    def handshake(self, **payload):
        res = self.post("/api/handshake", payload)
        self.assertEqual(res.status_code, 200, res.get_json())
        return res.get_json()

    def test_handshake_normal(self):
        for auth in (False, True):
            with self.subTest(authenticated=auth):
                data = self.handshake(attacker=False, authenticated=auth, message="hi bob")
                self.assertEqual(data["outcome"]["bob_received"], "hi bob")
                self.assertIsNone(data["outcome"]["mallory_read"])
                self.assertTrue(data["outcome"]["same_key"])
                self.assertTrue(all(s["ok"] is not False for s in data["steps"]))

    def test_mitm_without_signatures_succeeds(self):
        data = self.handshake(attacker=True, authenticated=False, message="secret plan")
        self.assertEqual(data["outcome"]["mallory_read"], "secret plan")
        self.assertEqual(data["outcome"]["bob_received"], "secret plan")
        self.assertFalse(data["outcome"]["detected"])

    def test_mitm_with_signatures_is_detected(self):
        data = self.handshake(attacker=True, authenticated=True, message="secret plan")
        self.assertTrue(data["outcome"]["detected"])
        self.assertIsNone(data["outcome"]["mallory_read"])
        self.assertIsNone(data["outcome"]["bob_received"])
        checks = [s for s in data["steps"] if s["kind"] in ("check", "alert") and s["ok"] is not None]
        self.assertTrue(checks and all(s["ok"] is False for s in checks))

    # ---- pages ----------------------------------------------------------
    def test_health_and_unknown_route(self):
        self.assertEqual(self.client.get("/api/health").get_json()["status"], "ok")
        self.assertEqual(self.client.get("/api/nope").status_code, 404)


if __name__ == "__main__":
    unittest.main()
