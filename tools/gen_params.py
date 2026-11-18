#!/usr/bin/env python3
"""Generate Schnorr-group parameters once and write poh/params.json.

    python3 tools/gen_params.py [--q-bits 256] [--k-bits 768]

p = k*q + 1 with q prime and p prime; g, h are random elements of the
order-q subgroup.  Deterministic only in the sense that the output file is
pinned; every run produces fresh randomness.
"""

from __future__ import annotations

import argparse
import json
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from poh.group import modpow  # noqa: E402

SMALL_PRIMES = [p for p in range(2, 2000) if all(p % d for d in range(2, int(p**0.5) + 1))]


def _trial_division(n: int) -> bool:
    """False if n is divisible by a small prime (n itself excluded)."""
    for sp in SMALL_PRIMES:
        if n == sp:
            return True
        if n % sp == 0:
            return False
    return True


def is_probable_prime(n: int, rounds: int = 32) -> bool:
    if n < 2:
        return False
    if not _trial_division(n):
        return False
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    bases = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    bases += [secrets.randbelow(n - 3) + 2 for _ in range(rounds)]
    for a in bases:
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def gen_prime(bits: int) -> int:
    while True:
        cand = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(cand):
            return cand


def subgroup_element(p: int, q: int, k: int) -> int:
    while True:
        x = secrets.randbelow(p - 3) + 2
        y = modpow(x, k, p)
        if y != 1:
            return y


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--q-bits", type=int, default=256)
    ap.add_argument("--k-bits", type=int, default=768)
    ap.add_argument("--out", default=str(Path(__file__).resolve().parents[1] / "poh" / "params.json"))
    args = ap.parse_args()

    q = gen_prime(args.q_bits)
    while True:
        k = secrets.randbits(args.k_bits) | 2  # even: q odd => k*q+1 is odd
        p = k * q + 1
        if is_probable_prime(p):
            break

    g = subgroup_element(p, q, k)
    h = subgroup_element(p, q, k)
    while h == g:
        h = subgroup_element(p, q, k)

    out = {
        "p": hex(p),
        "q": hex(q),
        "k": hex(k),
        "g": hex(g),
        "h": hex(h),
        "bits": {"p": p.bit_length(), "q": q.bit_length()},
    }
    Path(args.out).write_text(json.dumps(out, indent=2) + "\n")
    print(f"wrote {args.out}: p={p.bit_length()} bits, q={q.bit_length()} bits, k={k.bit_length()} bits")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
