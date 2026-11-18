# zk-proof (Proof of Humanity)

A reference implementation of zero-knowledge range proofs and nullifier-based Sybil resistance for Proof-of-Humanity systems.

## Overview

This project provides:

- **Zero-Knowledge Range Proofs**: Prove that a committed value lies in `[0, 2^n)` without revealing the value itself. Uses the CDS OR-proof construction over bit commitments.
  
- **Pedersen Commitments**: Perfectly hiding and binding commitment scheme (`C = g^v * h^r`).

- **Nullifier-Based Sybil Resistance**: Prevents the same Web2 account from being counted twice across multiple attestations using `nullifier = H(scope || H(user_sk))`.

- **Fiat-Shamir Hashing**: Non-interactive proofs via random oracle model.

### Architecture

```
poh/
├── __init__.py      # Package exports
├── group.py         # Schnorr-group parameters + Fiat-Shamir hashing
├── pedersen.py      # Pedersen commitment scheme
├── rangeproof.py    # CDS OR-proof range proofs (32-bit default)
└── nullifier.py     # Sybil-resistant nullifier mechanism
```

## Quick Start

### Prerequisites

- Python 3.8+

```bash
python3 --version
```

### Installation

Clone the repository:

```bash
git clone https://github.com/yourorg/zk-proof.git
cd zk-proof
```

No additional dependencies required—uses only Python standard library (`hashlib`, `json`, `secrets`, `dataclasses`).

## Usage

### 1. Load Group Parameters

```python
from poh import load_group, Group

group: Group = load_group()
print(f"Group order q bit length: {group.q.bit_length()}")
```

The package includes demo-sized parameters (`p ≈ 1024-bit`, `q ≈ 256-bit`) in `params.json`. For production, replace with BN254/BLS12-381.

### 2. Create a Pedersen Commitment

```python
from poh import commit

value = 12345
blinding = 7777  # Keep this secret!

commitment, _ = commit(group, value, blinding)
print(f"Commitment: {commitment}")
```

### 3. Prove Range Membership

```python
from poh import range_prove

# Prove value is in [0, 2^32)
commitment, proof = range_prove(group, value, blinding, bits=32)

print(f"Proof created: {type(proof).__name__}")
```

### 4. Verify the Range Proof

```python
from poh import range_verify

is_valid = range_verify(group, commitment, proof)
print(f"Range proof valid: {is_valid}")  # True
```

### 5. Generate Nullifiers for Sybil Resistance

```python
from poh import compute_nullifier_from_secret

# User's Web2 credentials (email, phone, etc.)
user_secret = b"user@example.com"
scope = b"poh/v1"  # Different scopes allow different attestations

nullifier = compute_nullifier_from_secret(group, scope, user_secret)
print(f"Nullifier: {nullifier}")
```

### 6. Register Nullifiers to Prevent Replay

```python
from poh import NullifierRegistry

registry = NullifierRegistry()

# First use succeeds
assert registry.register(nullifier) == True

# Duplicate (Sybil) attempt rejected
assert registry.register(nullifier) == False
```

## Complete Example

```python
from poh import (
    load_group,
    commit,
    range_prove,
    range_verify,
    compute_nullifier_from_secret,
    NullifierRegistry,
)

# Load parameters
group = load_group()

# User wants to prove they are > 18 years old (value = age)
age = 25
blinding = 9999

# Create commitment and prove age ∈ [0, 2^32)
commitment, proof = range_prove(group, age, blinding, bits=32)

# Verifier checks the proof
assert range_verify(group, commitment, proof), "Range proof invalid!"

# Generate nullifier for Sybil resistance
user_secret = b"user@example.com"
scope = b"poh/v1"

nullifier = compute_nullifier_from_secret(group, scope, user_secret)
registry = NullifierRegistry()

# First time: accepted
assert registry.register(nullifier) == True

# Second time (replay attack): rejected
assert registry.register(nullifier) == False

print("✓ All operations successful!")
```

## Running Tests

```bash
cd /home/clinebox/Cloud/GitHub/zk-proof

# Test imports work
python3 -c "from poh import *; print('Imports successful!')"

# Run nullifier tests (requires pytest)
pip install pytest
pytest tests/test_nullifier.py -v
```

Test coverage:
- Nullifier determinism
- Scope/user differentiation  
- Registry replay prevention
- Range proof validity

## Key Properties

| Property | Description |
|----------|-------------|
| **Zero-Knowledge** | Verifier learns only that the value is in range, not the value itself. |
| **Binding** | Committer cannot open to a different value (computational). |
| **Hiding** | Verifier learns nothing about the committed value (perfect). |
| **Non-Deterministic Proofs** | Same `(value, blinding)` produces different proofs each call (random challenges), but deterministic commitments. |
| **Sybil Resistance** | One `(scope, account)` pair → exactly one nullifier; reuse rejected. |

## Production Deployment

The current implementation uses demo-sized parameters for speed and clarity.

For production use:

1. **Replace parameters**: Use BN254 or BLS12-381 curve parameters.
2. **Tooling**: Generate proofs with arkworks (Rust), circom+snarkjs, or halo2.
3. **Nullifier Storage**: Replace `NullifierRegistry` with:
   - Database (PostgreSQL/MySQL) with unique constraint
   - Smart contract (Ethereum/L2) with storage slot for nullifiers

### Nullifier Integration Pattern

```python
# Production pattern (conceptual)
class DatabaseNullifierRegistry:
    def __init__(self, db_conn):
        self.db = db_conn
    
    def register(self, nullifier: int) -> bool:
        try:
            # INSERT with ON CONFLICT or unique constraint
            self.db.execute(
                "INSERT INTO nullifiers (nullifier) VALUES (?)",
                (nullifier,)
            )
            return True
        except IntegrityError:
            return False  # Already used
```

## References

- **CDS OR-proofs**: Canetti, Dodis, & Shamir (1997)—bit decomposition with range proofs.
- **Pedersen Commitments**: Pedersen (1991)—perfectly hiding commitment scheme.
- **Fiat-Shamir Heuristic**: Fiat & Shamir (1986)—transform interactive to non-interactive proofs.

## License

MIT
