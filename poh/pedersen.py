"""Pedersen commitments: C = g^v * h^r mod p (perfectly hiding, binding)."""

from __future__ import annotations

from .group import Group, modpow, rand_scalar


def commit(group: Group, value: int, blinding: int | None = None) -> tuple[int, int]:
    """Return (C, r).  Callers that need the opening must keep r."""
    r = rand_scalar(group.q) if blinding is None else blinding % group.q
    c = modpow(group.g, value % group.q, group.p) * modpow(group.h, r, group.p) % group.p
    return c, r


def verify_opening(group: Group, c: int, value: int, blinding: int) -> bool:
    expected = (
        modpow(group.g, value % group.q, group.p)
        * modpow(group.h, blinding % group.q, group.p)
        % group.p
    )
    return c % group.p == expected


def shift(group: Group, c: int, delta: int) -> int:
    """C * g^delta mod p -- shifts the committed value by delta (may be negative)."""
    return c * modpow(group.g, delta % group.q, group.p) % group.p
