"""poh - zero-knowledge Proof-of-Humanity reference implementation.

This package provides:
- `group`: Schnorr-group parameters and Fiat-Shamir hashing
- `pedersen`: Pedersen commitment scheme (C = g^v * h^r)
- `rangeproof`: CDS OR-proof that a committed value lies in [0, 2^n)
- `nullifier`: Sybil-resistant nullifier mechanism with replay prevention

NOTE: Current implementation uses demo-sized parameters (1024-bit p).
For production use, migrate to BN254/BLS12-381 via arkworks or circom+snarkjs.
"""

from __future__ import annotations

from .group import Group, load_group, hash_to_scalar, params_fingerprint
from .pedersen import commit, verify_opening, shift
from .rangeproof import RangeProof, prove as range_prove, verify as range_verify
from .nullifier import (
    compute_nullifier,
    compute_nullifier_from_secret,
    derive_user_sk,
    NullifierRegistry,
)

__version__ = "0.1.0"
