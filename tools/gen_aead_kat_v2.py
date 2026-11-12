#!/usr/bin/env python3
# Independent generator for the suite-2 AEAD known-answer fixture
# (tests/fixtures/aead_kat_v2/frozen.hex).
#
# It computes every expected value from the primitives alone
# (BLAKE3 derive-key for the deterministic test inputs, HKDF-SHA256 for the
# key schedule, AES-256-GCM for the sealing) exactly as design-aad-suite.md
# section 1.2 and 1.3 define them. It does not call the Rust library, so the
# fixture is an independent witness the Rust test is checked against, not a
# transcript of the implementation's output.
#
# No key, nonce, salt or password is a literal here: each is derived with
# BLAKE3 in key-derivation mode from a label. The Rust test derives the same
# inputs from the same labels with the same context string, so both sides
# agree without sharing a secret.
#
# Run by hand once, after a deliberate format change, and commit the result:
#   python tools/gen_aead_kat_v2.py > crates/miasma-core/tests/fixtures/aead_kat_v2/frozen.hex

import blake3
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

CTX = "miasma aead known answers v2 (test-only)"


def fill(label: str, n: int) -> bytes:
    return blake3.blake3(label.encode(), derive_key_context=CTX).digest(length=n)


def hkdf(salt, ikm, info, n=32):
    return HKDF(algorithm=hashes.SHA256(), length=n, salt=salt, info=info).derive(ikm)


# --- The 49-byte canonical AAD (section 1.2) --------------------------------
def encode_aad(suite, context, mid, segment_index, k, n, plaintext_len):
    assert len(mid) == 32
    out = bytearray()
    out += b"MSA2"
    out += suite.to_bytes(2, "little")
    out += bytes([context])
    out += mid
    out += segment_index.to_bytes(4, "little")
    out += bytes([k])
    out += bytes([n])
    out += plaintext_len.to_bytes(4, "little")
    assert len(out) == 49, len(out)
    return bytes(out)


SUITE2 = 2
SEG_LABEL = b"miasma-seg-key-v2"
NAME_LABEL = b"miasma-name-key-v2"

# Deterministic test inputs.
mid = fill("mid digest", 32)
k_enc = fill("segment random key K_enc", 32)
nonce = fill("aes nonce", 12)
pw_key = fill("password key pw_key", 32)
name = "kat-name-v2.txt"

lines = []
lines.append(
    "# AES-256-GCM suite-2 known answers (49-byte AAD, miasma-seg-key-v2, "
    "miasma-name-key-v2). Computed independently by tools/gen_aead_kat_v2.py "
    "from the primitives; never regenerate to make a test pass."
)
lines.append(f"mid {mid.hex()}")
lines.append(f"k_enc {k_enc.hex()}")
lines.append(f"nonce {nonce.hex()}")
lines.append(f"pw_key {pw_key.hex()}")

# One AAD per context, plus the sealed-segment key, ciphertext per context.
# context 1 = transfer segment, 2 = whole-file, 3 = directed content.
cases = [
    # label, context, segment_index, k, n, plaintext_len, with_password
    ("transfer", 1, 2, 4, 6, 64, True),
    ("wholefile", 2, 0, 3, 5, 64, False),
    ("directed", 3, 0, 3, 5, 40, False),
]

for label, ctx, seg_idx, k, n, ptlen, with_pw in cases:
    pt = fill(f"plaintext {label}", ptlen)
    aad = encode_aad(SUITE2, ctx, mid, seg_idx, k, n, ptlen)
    salt = pw_key if with_pw else None
    info = SEG_LABEL + aad
    k_aes = hkdf(salt, k_enc, info, 32)
    ct = AESGCM(k_aes).encrypt(nonce, pt, aad)
    assert len(pt) == ptlen
    lines.append(f"aad_{label} {aad.hex()}")
    lines.append(f"kaes_{label} {k_aes.hex()}")
    lines.append(f"ct_{label} {ct.hex()}")

# Sealed name v2: aad = "MSN2" || suite(u16le) || mid ; label = miasma-name-key-v2.
name_aad = b"MSN2" + SUITE2.to_bytes(2, "little") + mid
name_key = hkdf(pw_key, mid, NAME_LABEL, 32)
name_nonce = fill("name nonce", 12)
name_ct = AESGCM(name_key).encrypt(name_nonce, name.encode(), name_aad)
lines.append(f"name_aad {name_aad.hex()}")
lines.append(f"name_key {name_key.hex()}")
lines.append(f"name_nonce {name_nonce.hex()}")
lines.append(f"name_sealed {(name_nonce + name_ct).hex()}")

print("\n".join(lines))
