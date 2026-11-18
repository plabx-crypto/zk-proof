"""Schnorr-group parameters, modular arithmetic and Fiat-Shamir hashing.

The group is a prime-order subgroup of Z_p^*:
    p = k*q + 1, q prime, g = h^k mod p (order q), h2 = h2'^k mod p.

NOTE ON PARAMETERS: params.json ships a demo-sized group (p ~ 1024 bit,
q ~ 256 bit).  That is fine for a reference implementation but NOT
production: use BN254 / BLS12-381 (arkworks, circom+snarkjs, halo2) there.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass
from pathlib import Path

PARAMS_PATH = Path(__file__).with_name("params.json")


@dataclass(frozen=True)
class Group:
    p: int
    q: int
    k: int
    g: int
    h: int

    @property
    def modulus_bytes(self) -> int:
        return (self.p.bit_length() + 7) // 8


def load_group(path: Path | None = None) -> Group:
    raw = json.loads((path or PARAMS_PATH).read_text())
    return Group(
        p=int(raw["p"], 16),
        q=int(raw["q"], 16),
        k=int(raw["k"], 16),
        g=int(raw["g"], 16),
        h=int(raw["h"], 16),
    )


def modpow(base: int, exp: int, mod: int) -> int:
    return pow(base, exp, mod)


def modinv(a: int, mod: int) -> int:
    return pow(a % mod, -1, mod)


def rand_scalar(q: int) -> int:
    """Uniform scalar in [0, q)."""
    return secrets.randbelow(q)


def _length_prefixed(*parts: bytes) -> bytes:
    out = bytearray()
    for part in parts:
        out += len(part).to_bytes(4, "big")
        out += part
    return bytes(out)


def i2b(x: int, length: int | None = None) -> bytes:
    if length is None:
        length = max(1, (x.bit_length() + 7) // 8)
    return x.to_bytes(length, "big")


def b2i(b: bytes) -> int:
    return int.from_bytes(b, "big")


def sha256(*parts: bytes) -> bytes:
    return hashlib.sha256(_length_prefixed(*parts)).digest()


def hash_to_scalar(group: Group, *parts: bytes) -> int:
    """Fiat-Shamir challenge: SHA-256 over length-prefixed parts, mod q."""
    return b2i(sha256(*parts)) % group.q


def params_fingerprint(group: Group) -> str:
    """Stable digest of the public parameters (pinned by clients)."""
    blob = _length_prefixed(
        i2b(group.p), i2b(group.q), i2b(group.k), i2b(group.g), i2b(group.h)
    )
    return hashlib.sha256(blob).hexdigest()
