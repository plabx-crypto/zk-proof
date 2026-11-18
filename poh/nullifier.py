"""Nullifier mechanism: H(scope || user_secret) prevents Sybil attacks.

One Web2 account + scope yields exactly one nullifier, preventing the same
account from being counted twice across multiple attestations.
"""

from __future__ import annotations

from dataclasses import dataclass

from .group import Group, sha256, i2b


def derive_user_sk(user_secret: bytes) -> bytes:
    """Derive a unique user secret key from the user's Web2 credentials."""
    return sha256(b"poh/nullifier/user_sk/v1", user_secret)


def compute_nullifier(group: Group, scope: bytes, user_sk: bytes) -> int:
    """Compute nullifier = H(scope || user_sk) mod q.
    
    This ensures one (scope, account) pair yields exactly one nullifier,
    preventing proof reuse across multiple attestations (Sybil resistance).
    """
    return int.from_bytes(sha256(
        b"poh/nullifier/v1",
        i2b(len(scope), 4),
        scope,
        user_sk
    ), "big") % group.q


def compute_nullifier_from_secret(group: Group, scope: bytes, user_secret: bytes) -> int:
    """Convenience wrapper: derive user_sk and compute nullifier."""
    return compute_nullifier(group, scope, derive_user_sk(user_secret))


@dataclass(frozen=True)
class NullifierProof:
    """Zero-knowledge proof that a nullifier was derived correctly.
    
    This proves knowledge of user_sk such that nullifier = H(scope || H(user_sk))
    without revealing user_sk itself.
    """
    nullifier: int
    commitment_to_sk: int  # C_sk = g^sk * h^r
    r: int  # blinding for sk commitment
    proof_zk: bytes  # ZK proof bytes (can be extended later)


class NullifierRegistry:
    """Stateful registry to track used nullifiers and prevent replay.
    
    A verifier should maintain one instance and reject any proof whose
    nullifier has been seen before. This enforces uniqueness of (C, auth)
    pairs across multiple attestations.
    """
    
    def __init__(self) -> None:
        self._used_nullifiers: set[int] = set()
    
    def register(self, nullifier: int) -> bool:
        """Register a nullifier and return False if it was already used.
        
        Returns True if the nullifier is new (valid for use).
        Returns False if the nullifier was previously registered (replay attempt).
        """
        if nullifier in self._used_nullifiers:
            return False
        self._used_nullifiers.add(nullifier)
        return True
    
    def is_used(self, nullifier: int) -> bool:
        """Check if a nullifier has been used before."""
        return nullifier in self._used_nullifiers
    
    def reset(self) -> None:
        """Clear all registered nullifiers (for testing purposes)."""
        self._used_nullifiers.clear()
    
    @property
    def count(self) -> int:
        """Number of unique nullifiers registered."""
        return len(self._used_nullifiers)