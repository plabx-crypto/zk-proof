"""Zero-knowledge range proof: committed value lies in [0, 2^n).

Construction (CDS OR-proofs over bit commitments):

1. Decompose v into bits b_0..b_{n-1} and commit to each bit with fresh
   blinding:  C_i = g^{b_i} * h^{r_i}.
2. For every bit, prove with a 2-branch CDS OR-proof (base h) that C_i opens
   to 0 or to 1:
       branch 0: C_i      = h^{r_i}
       branch 1: C_i / g  = h^{r_i}
3. Prove consistency of the decomposition:
       D = C * (prod_i C_i^{2^i})^{-1} = h^{r'} ,  r' = r - sum_i r_i*2^i
   with a Schnorr proof of knowledge of log_h(D).

Verification recomputes every Fiat-Shamir challenge, so a proof only verifies
for the exact commitment, bit commitments and transcript it was made for.
"""

from __future__ import annotations

from dataclasses import dataclass

from .group import (
    Group,
    hash_to_scalar,
    i2b,
    modinv,
    modpow,
    rand_scalar,
)
from .pedersen import commit

DOMAIN_BIT = b"poh/rangeproof/bit/v1"
DOMAIN_CONSISTENCY = b"poh/rangeproof/consistency/v1"


@dataclass(frozen=True)
class BitProof:
    """CDS OR-proof that a bit commitment opens to 0 or 1."""

    a0: int
    a1: int
    c0: int
    c1: int
    s0: int
    s1: int


@dataclass(frozen=True)
class RangeProof:
    bits: int
    commitment: int  # The main Pedersen commitment C = g^v * h^r
    commitments: tuple[int, ...]  # Bit commitments C_i = g^{b_i} * h^{r_i}
    bit_proofs: tuple[BitProof, ...]
    consistency_a: int
    consistency_s: int


def _bit_challenge(group: Group, index: int, c: int, ci: int, a0: int, a1: int) -> int:
    return hash_to_scalar(
        group,
        DOMAIN_BIT,
        i2b(index, 4),
        i2b(c, group.modulus_bytes),
        i2b(ci, group.modulus_bytes),
        i2b(a0, group.modulus_bytes),
        i2b(a1, group.modulus_bytes),
    )


def _in_subgroup(group: Group, x: int) -> bool:
    """Reject 0, out-of-range values and elements outside the order-q subgroup."""
    return 0 < x < group.p and modpow(x, group.q, group.p) == 1


def _prove_bit(
    group: Group, index: int, c: int, ci: int, bit: int, r: int
) -> BitProof:
    g, h, p, q = group.g, group.h, group.p, group.q
    target0 = ci
    target1 = ci * modinv(g, p) % p
    if bit == 0:
        k = rand_scalar(q)
        a0 = modpow(h, k, p)
        c1 = rand_scalar(q)
        s1 = rand_scalar(q)
        a1 = modpow(h, s1, p) * modpow(modinv(target1, p), c1, p) % p
        real = 0
    else:
        k = rand_scalar(q)
        a1 = modpow(h, k, p)
        c0 = rand_scalar(q)
        s0 = rand_scalar(q)
        a0 = modpow(h, s0, p) * modpow(modinv(target0, p), c0, p) % p
        real = 1
    total = _bit_challenge(group, index, c, ci, a0, a1)
    if real == 0:
        c0 = (total - c1) % q
        s0 = (k + c0 * r) % q
    else:
        c1 = (total - c0) % q
        s1 = (k + c1 * r) % q
    return BitProof(a0=a0, a1=a1, c0=c0, c1=c1, s0=s0, s1=s1)


def _verify_bit(group: Group, index: int, c: int, ci: int, proof: BitProof) -> bool:
    """Check a single CDS OR-proof against the challenge recomputed from scratch."""
    g, h, p, q = group.g, group.h, group.p, group.q
    if not all(
        isinstance(x, int) and 0 <= x < q
        for x in (proof.c0, proof.c1, proof.s0, proof.s1)
    ):
        return False
    if not _in_subgroup(group, proof.a0) or not _in_subgroup(group, proof.a1):
        return False
    total = _bit_challenge(group, index, c, ci, proof.a0, proof.a1)
    if (proof.c0 + proof.c1) % q != total:
        return False
    target0 = ci
    target1 = ci * modinv(g, p) % p
    if modpow(h, proof.s0, p) != proof.a0 * modpow(target0, proof.c0, p) % p:
        return False
    return modpow(h, proof.s1, p) == proof.a1 * modpow(target1, proof.c1, p) % p


def _consistency_challenge(
    group: Group, commitments: tuple[int, ...], c: int, a: int
) -> int:
    """Bind the whole transcript: commitment, every bit commitment, announcement."""
    parts = [DOMAIN_CONSISTENCY, i2b(len(commitments), 4), i2b(c, group.modulus_bytes)]
    parts += [i2b(ci, group.modulus_bytes) for ci in commitments]
    parts.append(i2b(a, group.modulus_bytes))
    return hash_to_scalar(group, *parts)


def _commitment_product(group: Group, commitments: tuple[int, ...]) -> int:
    """prod_i C_i^{2^i} mod p using correct Horner's method (MSB to LSB)."""
    p = group.p
    # Process bits from MSB to LSB for correct exponentiation
    rev = tuple(reversed(commitments))
    acc = 1
    for ci in rev:
        acc = acc * acc % p * ci % p
    return acc


def _prove_consistency(
    group: Group, c: int, commitments: tuple[int, ...], r_prime: int
) -> tuple[int, int]:
    """Schnorr proof of knowledge of log_h(D), D = C * prod_i C_i^{-2^i}."""
    k = rand_scalar(group.q)
    a = modpow(group.h, k, group.p)
    e = _consistency_challenge(group, commitments, c, a)
    s = (k + e * r_prime) % group.q
    return a, s


def _verify_consistency(
    group: Group,
    c: int,
    commitments: tuple[int, ...],
    a: int,
    s: int,
) -> bool:
    p, q, h = group.p, group.q, group.h
    if not isinstance(s, int) or not 0 <= s < q:
        return False
    if not _in_subgroup(group, a):
        return False
    d = c * modinv(_commitment_product(group, commitments), p) % p
    if not _in_subgroup(group, d):
        return False
    e = _consistency_challenge(group, commitments, c, a)
    return modpow(h, s, p) == a * modpow(d, e, p) % p


def _check_bits(group: Group, bits: int) -> None:
    """Reject ranges that cannot be represented unambiguously modulo q."""
    if not isinstance(bits, int) or bits < 1:
        raise ValueError("bits must be a positive integer")
    if bits >= group.q.bit_length():
        raise ValueError(
            f"bits must be < {group.q.bit_length()} for the group order q"
        )


def prove(group: Group, value: int, blinding: int, bits: int = 32) -> tuple[int, RangeProof]:
    """Prove that ``C = g^value * h^blinding`` commits to a value in [0, 2^bits).

    The caller keeps ``blinding`` secret; only the returned proof (plus the
    commitment) is handed to the verifier.  ``bits`` must satisfy
    ``1 <= bits < q.bit_length()`` so that ``2^bits <= q`` and the bit
    decomposition of the committed value is unique.

    Returns:
        Tuple of (commitment, RangeProof).
    """
    _check_bits(group, bits)
    if not isinstance(value, int) or not 0 <= value < (1 << bits):
        raise ValueError(f"value must be an integer in [0, 2^{bits})")
    p, h = group.p, group.h
    r = blinding % group.q
    c, _ = commit(group, value, r)

    bit_values = [(value >> i) & 1 for i in range(bits)]
    bit_randoms = [rand_scalar(group.q) for _ in range(bits)]
    commitments = tuple(
        modpow(group.g, b, p) * modpow(h, ri, p) % p
        for b, ri in zip(bit_values, bit_randoms)
    )
    bit_proofs = tuple(
        _prove_bit(group, i, c, commitments[i], bit_values[i], bit_randoms[i])
        for i in range(bits)
    )
    r_prime = (r - sum(ri << i for i, ri in enumerate(bit_randoms))) % group.q
    consistency_a, consistency_s = _prove_consistency(group, c, commitments, r_prime)
    proof = RangeProof(
        bits=bits,
        commitment=c,
        commitments=commitments,
        bit_proofs=bit_proofs,
        consistency_a=consistency_a,
        consistency_s=consistency_s,
    )
    return c, proof


def verify(group: Group, commitment: int, proof: RangeProof) -> bool:
    """Return True iff ``proof`` shows ``commitment`` opens to a value in [0, 2^n).

    Every Fiat-Shamir challenge is recomputed, so a proof is bound to this
    exact commitment, these exact bit commitments and this bit length.
    """
    if not isinstance(proof, RangeProof) or not isinstance(commitment, int):
        return False
    n = proof.bits
    try:
        _check_bits(group, n)
    except ValueError:
        return False
    if len(proof.commitments) != n or len(proof.bit_proofs) != n:
        return False
    if not _in_subgroup(group, commitment):
        return False
    if any(not _in_subgroup(group, ci) for ci in proof.commitments):
        return False
    for i in range(n):
        if not _verify_bit(group, i, commitment, proof.commitments[i], proof.bit_proofs[i]):
            return False
    return _verify_consistency(
        group,
        commitment,
        proof.commitments,
        proof.consistency_a,
        proof.consistency_s,
    )

