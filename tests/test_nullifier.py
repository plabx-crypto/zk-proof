"""Tests for nullifier mechanism and Sybil resistance."""

import pytest

from poh import Group, load_group, compute_nullifier, derive_user_sk, NullifierRegistry


@pytest.fixture(scope="module")
def group() -> Group:
    return load_group()


class TestNullifierDerivation:
    """Test nullifier derivation from user secrets."""
    
    def test_same_scope_and_secret_yields_same_nullifier(self, group: Group) -> None:
        """Identical inputs must produce identical nullifiers."""
        scope = b"poh/v1"
        secret = b"user@example.com"
        
        n1 = compute_nullifier_from_secret(group, scope, secret)
        n2 = compute_nullifier_from_secret(group, scope, secret)
        
        assert n1 == n2
    
    def test_different_scope_yields_different_nullifier(self, group: Group) -> None:
        """Different scopes must produce different nullifiers for same user."""
        secret = b"user@example.com"
        
        n1 = compute_nullifier_from_secret(group, b"scope1", secret)
        n2 = compute_nullifier_from_secret(group, b"scope2", secret)
        
        assert n1 != n2
    
    def test_different_user_yields_different_nullifier(self, group: Group) -> None:
        """Different users must produce different nullifiers for same scope."""
        scope = b"poh/v1"
        
        n1 = compute_nullifier_from_secret(group, scope, b"user1@example.com")
        n2 = compute_nullifier_from_secret(group, scope, b"user2@example.com")
        
        assert n1 != n2
    
    def test_nullifier_in_valid_range(self, group: Group) -> None:
        """Nullifier must be in [0, q)."""
        scope = b"poh/v1"
        secret = b"user@example.com"
        
        nullifier = compute_nullifier_from_secret(group, scope, secret)
        
        assert 0 <= nullifier < group.q
    
    def test_derive_user_sk_deterministic(self) -> None:
        """User SK derivation must be deterministic."""
        secret = b"my-secret"
        
        sk1 = derive_user_sk(secret)
        sk2 = derive_user_sk(secret)
        
        assert sk1 == sk2


class TestNullifierRegistry:
    """Test nullifier registry for replay prevention."""
    
    def test_new_nullifier_is_accepted(self, group: Group) -> None:
        """First use of a nullifier must be accepted."""
        scope = b"poh/v1"
        secret = b"user@example.com"
        
        registry = NullifierRegistry()
        nullifier = compute_nullifier_from_secret(group, scope, secret)
        
        assert registry.register(nullifier) is True
    
    def test_duplicate_nullifier_is_rejected(self, group: Group) -> None:
        """Same nullifier used twice must be rejected (Sybil protection)."""
        scope = b"poh/v1"
        secret = b"user@example.com"
        
        registry = NullifierRegistry()
        nullifier = compute_nullifier_from_secret(group, scope, secret)
        
        # First use succeeds
        assert registry.register(nullifier) is True
        
        # Second use fails (replay detection)
        assert registry.register(nullifier) is False    
    def test_is_used_detects_registered_nullifiers(self, group: Group) -> None:
        """is_used must correctly identify registered vs. unregistered nullifiers."""
        scope = b"poh/v1"
        secret1 = b"user1@example.com"
        secret2 = b"user2@example.com"
        
        registry = NullifierRegistry()
        n1 = compute_nullifier_from_secret(group, scope, secret1)
        n2 = compute_nullifier_from_secret(group, scope, secret2)
        
        # Neither registered yet
        assert not registry.is_used(n1)
        assert not registry.is_used(n2)
        
        # Register one
        registry.register(n1)
        
        # Now only the registered one is "used"
        assert registry.is_used(n1)
        assert not registry.is_used(n2)
    
    def test_reset_clears_registry(self, group: Group) -> None:
        """Reset must clear all tracked nullifiers."""
        scope = b"poh/v1"
        secret = b"user@example.com"
        
        registry = NullifierRegistry()
        nullifier = compute_nullifier_from_secret(group, scope, secret)
        
        registry.register(nullifier)
        assert registry.is_used(nullifier)
        
        registry.reset()
        assert not registry.is_used(nullifier)
    
    def test_count_tracks_unique_nullifiers(self, group: Group) -> None:
        """Count must reflect number of unique nullifiers registered."""
        registry = NullifierRegistry()
        
        for i in range(5):
            secret = f"user{i}@example.com".encode()
            nullifier = compute_nullifier_from_secret(group, b"poh/v1", secret)
            registry.register(nullifier)
        
        assert registry.count == 5
    
    def test_count_unchanged_on_duplicate(self, group: Group) -> None:
        """Duplicate registrations must not increase count."""
        scope = b"poh/v1"
        secret = b"user@example.com"
        
        registry = NullifierRegistry()
        nullifier = compute_nullifier_from_secret(group, scope, secret)
        
        registry.register(nullifier)
        initial_count = registry.count
        
        registry.register(nullifier)  # duplicate
        assert registry.count == initial_count
    
    def test_multiple_scopes_independent(self, group: Group) -> None:
        """Nullifiers from different scopes must be tracked independently."""
        registry = NullifierRegistry()
        
        n1 = compute_nullifier_from_secret(group, b"scope1", b"user@example.com")
        n2 = compute_nullifier_from_secret(group, b"scope2", b"user@example.com")
        
        # Different nullifiers for different scopes (even same user)
        assert n1 != n2
        
        registry.register(n1)
        assert registry.is_used(n1)
        assert not registry.is_used(n2)  # scope2 still usable


class TestSybilResistance:
    """Test that the mechanism prevents Sybil/proof-reuse attacks."""
    
    def test_cannot_reuse_proof_with_same_nullifier(self, group: Group) -> None:
        """An attacker cannot reuse a valid nullifier twice."""
        registry = NullifierRegistry()
        scope = b"poh/v1"
        secret = b"attacker@example.com"
        
        nullifier = compute_nullifier_from_secret(group, scope, secret)
        
        # First verification succeeds
        assert registry.register(nullifier) is True
        
        # Second attempt (Sybil attack) fails
        assert registry.register(nullifier) is False
    
    def test_legitimate_new_user_has_different_nullifier(self, group: Group) -> None:
        """Different legitimate users must have different nullifiers."""
        registry = NullifierRegistry()
        
        n1 = compute_nullifier_from_secret(group, b"poh/v1", b"user1@example.com")
        n2 = compute_nullifier_from_secret(group, b"poh/v1", b"user2@example.com")
        n3 = compute_nullifier_from_secret(group, b"poh/v1", b"user3@example.com")
        
        # All different
        assert len({n1, n2, n3}) == 3
        
        # All can register successfully
        assert registry.register(n1)
        assert registry.register(n2)
        assert registry.register(n3)
    
    def test_nullifier_is_hash_based_not_secret(self, group: Group) -> None:
        """Nullifier must be derived via hash (not just secret copy)."""
        scope = b"poh/v1"
        secret = b"secret-key-12345"
        
        nullifier = compute_nullifier_from_secret(group, scope, secret)
        
        # Nullifier should not equal the raw secret
        assert nullifier != int.from_bytes(secret, "big")
        
        # But deterministically derived from it
        expected = compute_nullifier(
            group,
            scope,
            derive_user_sk(secret)
        )
        assert nullifier == expected


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
