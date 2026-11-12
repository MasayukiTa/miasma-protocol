#!/usr/bin/env python3
"""Independent reference values for the Suite2 manifest-reader fixtures (WP-A4).

Writes two frozen files from the design's definitions alone, not from the
library's output:

  tests/fixtures/transfer_v4/frozen.hex   -- a transfer's Suite2 shares, the
      49-byte transfer-context AAD of each segment (design 1.2), and the
      per-slot piece commitment of each share (design 1.8).
  tests/fixtures/wholefile_v2/frozen.hex  -- a manifest-less Suite2 share set in
      the whole-file (context 2) and directed-body (context 3) shapes, their
      AADs, the piece commitments, and the AES-256-GCM known answers of the v2
      key schedule (design 1.3) for a representative segment.

Every secret-shaped input (mid, K_enc, key_share, nonce, pw_key) is derived with
BLAKE3 in key-derivation mode over a label and a fixed context string -- the
same construction the Rust test uses -- so neither side carries a literal and
both compute the same value without sharing one. Nothing here reads the Rust
library; the Rust test compares the library's output against these bytes.

Run by hand, once, to (re)write the two frozen files:
    python tools/gen_transfer_v4_fixtures.py
"""

import os

import blake3
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256

# Must match CTX in the Rust test (wire_compat_transfer_v4_test.rs).
CTX = "miasma transfer v4 reader fixtures (test-only)"

AAD_MAGIC = b"MSA2"
SUITE2 = 2
SEG_LABEL = b"miasma-seg-key-v2"

# Two segments, k=4 n=6, a short tail segment -- the same shape as the v3
# transfer fixture so the reader paths line up.
K, N = 4, 6
SEG_SIZE = 64
TOTAL_BYTES = 100
SEGMENTS = [(0, 0, SEG_SIZE), (1, SEG_SIZE, TOTAL_BYTES)]  # (index, start, end)


def fill(label: str, n: int) -> bytes:
    """BLAKE3 derive_key(CTX) over the label, XOF-expanded to n bytes."""
    h = blake3.blake3(label.encode(), derive_key_context=CTX)
    return h.digest(length=n)


def mid() -> bytes:
    return fill("mid digest", 32)


def aad(context: int, seg_index: int, plaintext_len: int) -> bytes:
    """The canonical 49-byte Suite2 segment AAD (design 1.2)."""
    out = bytearray(49)
    out[0:4] = AAD_MAGIC
    out[4:6] = SUITE2.to_bytes(2, "little")
    out[6] = context
    out[7:39] = mid()
    out[39:43] = seg_index.to_bytes(4, "little")
    out[43] = K
    out[44] = N
    out[45:49] = plaintext_len.to_bytes(4, "little")
    return bytes(out)


def derive_segment_key_v2(k_enc: bytes, pw_key, aad_bytes: bytes) -> bytes:
    """K_aes = HKDF-SHA256(salt=pw_key or empty, ikm=K_enc,
                           info="miasma-seg-key-v2" || AAD)  (design 1.3)."""
    info = SEG_LABEL + aad_bytes
    salt = pw_key if pw_key is not None else b""
    return HKDF(algorithm=SHA256(), length=32, salt=salt, info=info).derive(k_enc)


def seal(k_enc: bytes, nonce: bytes, plaintext: bytes, aad_bytes: bytes, pw_key) -> bytes:
    key = derive_segment_key_v2(k_enc, pw_key, aad_bytes)
    return AESGCM(key).encrypt(nonce, plaintext, aad_bytes)


def piece_commitment(version: int, seg_index: int, slot: int, original_len: int,
                     shard_data: bytes, key_share: bytes, nonce: bytes) -> bytes:
    """Domain-separated BLAKE3 over the whole share (design 1.8 / share.rs)."""
    h = blake3.blake3(derive_key_context="miasma-piece-commitment-v2")
    h.update(bytes([version]))
    h.update(mid())
    h.update(seg_index.to_bytes(4, "little"))
    h.update(slot.to_bytes(2, "little"))
    h.update(original_len.to_bytes(4, "little"))
    h.update(len(shard_data).to_bytes(8, "little"))
    h.update(shard_data)
    h.update(len(key_share).to_bytes(8, "little"))
    h.update(key_share)
    h.update(nonce)
    return h.digest(length=32)


def share_inputs(seg_index: int, slot: int):
    """The decided inputs of one v2 share: shard_data, key_share, nonce,
    original_len. Fully determined by the labels, so the Rust side rebuilds the
    identical share with new_v2 and the same fill()."""
    shard_data = fill(f"seg{seg_index} slot{slot} shard_data", 24)
    key_share = fill(f"seg{seg_index} slot{slot} key_share", 33)
    nonce = fill(f"seg{seg_index} slot{slot} nonce", 12)
    original_len = SEGMENTS[seg_index][2] - SEGMENTS[seg_index][1]
    return shard_data, key_share, nonce, original_len


def lines_transfer_v4():
    out = []
    out.append("# Suite2 (manifest v4) transfer reader fixtures. Computed independently by")
    out.append("# tools/gen_transfer_v4_fixtures.py from the design definitions (1.2 AAD,")
    out.append("# 1.8 piece commitment); never regenerate to make a test pass.")
    out.append(f"mid {mid().hex()}")
    for seg_index, start, end in SEGMENTS:
        plaintext_len = end - start
        out.append(f"aad_transfer_seg{seg_index} {aad(1, seg_index, plaintext_len).hex()}")
        for slot in range(N):
            sd, ks, nc, ol = share_inputs(seg_index, slot)
            pc = piece_commitment(2, seg_index, slot, ol, sd, ks, nc)
            out.append(f"shard_data_seg{seg_index}_slot{slot} {sd.hex()}")
            out.append(f"key_share_seg{seg_index}_slot{slot} {ks.hex()}")
            out.append(f"nonce_seg{seg_index}_slot{slot} {nc.hex()}")
            out.append(f"piece_commit_seg{seg_index}_slot{slot} {pc.hex()}")
    return out


def lines_wholefile_v2():
    out = []
    out.append("# Suite2 manifest-less share set, whole-file (context 2) and directed-body")
    out.append("# (context 3) shapes. AAD and AES-256-GCM known answers of the v2 key")
    out.append("# schedule (design 1.2, 1.3) and the piece commitment (1.8), computed")
    out.append("# independently by tools/gen_transfer_v4_fixtures.py. Never regenerate to")
    out.append("# make a test pass.")
    out.append(f"mid {mid().hex()}")

    # One representative segment (index 0), its shares, and the v2 AEAD known
    # answers in both the whole-file and directed contexts, with and without a
    # password key.
    seg_index = 0
    plaintext = fill("wholefile plaintext", SEG_SIZE)
    plaintext_len = len(plaintext)
    k_enc = fill("wholefile K_enc", 32)
    pw_key = fill("wholefile pw_key", 32)
    nonce = fill("wholefile nonce", 12)
    out.append(f"k_enc {k_enc.hex()}")
    out.append(f"pw_key {pw_key.hex()}")
    out.append(f"nonce {nonce.hex()}")
    out.append(f"plaintext {plaintext.hex()}")

    for ctx_name, ctx in (("wholefile", 2), ("directed", 3)):
        a = aad(ctx, seg_index, plaintext_len)
        out.append(f"aad_{ctx_name} {a.hex()}")
        kaes = derive_segment_key_v2(k_enc, None, a)
        out.append(f"kaes_{ctx_name} {kaes.hex()}")
        out.append(f"ct_{ctx_name} {seal(k_enc, nonce, plaintext, a, None).hex()}")
        kaes_pw = derive_segment_key_v2(k_enc, pw_key, a)
        out.append(f"kaes_{ctx_name}_pw {kaes_pw.hex()}")
        out.append(f"ct_{ctx_name}_pw {seal(k_enc, nonce, plaintext, a, pw_key).hex()}")

    # The manifest-less share set (version-2 shares) that a reader splits by
    # version. Same fill() inputs as transfer_v4 seg 0 so both files agree.
    for slot in range(N):
        sd, ks, nc, ol = share_inputs(seg_index, slot)
        pc = piece_commitment(2, seg_index, slot, ol, sd, ks, nc)
        out.append(f"shard_data_slot{slot} {sd.hex()}")
        out.append(f"key_share_slot{slot} {ks.hex()}")
        out.append(f"nonce_slot{slot} {nc.hex()}")
        out.append(f"piece_commit_slot{slot} {pc.hex()}")
    return out


def write(path, lines):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")
    print("wrote", path, f"({len(lines)} lines)")


def main():
    base = os.path.join("crates", "miasma-core", "tests", "fixtures")
    write(os.path.join(base, "transfer_v4", "frozen.hex"), lines_transfer_v4())
    write(os.path.join(base, "wholefile_v2", "frozen.hex"), lines_wholefile_v2())


if __name__ == "__main__":
    main()
