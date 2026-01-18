"""
Property-based tests for IP classification CRUD operations.

**Feature: ip-intelligence-analyzer, Property 12: Classification CRUD Operations**
**Validates: Requirements 6.6**
"""

import tempfile
from pathlib import Path
from hypothesis import given, strategies as st, assume
from hypothesis.strategies import composite

from src.ip_mana.config import ConfigManager, ClassificationRule


@composite
def valid_classification_rules(draw):
    """Generate valid classification rules."""
    name = draw(
        st.text(
            min_size=1,
            max_size=50,
            alphabet=st.characters(
                whitelist_categories=(
                    'Lu',
                    'Ll',
                    'Nd'),
                whitelist_characters='_-')))

    # Generate valid IP ranges
    ip_version = draw(st.integers(min_value=4, max_value=6))
    if ip_version == 4:
        # IPv4 ranges
        octets = [draw(st.integers(min_value=0, max_value=255)) for _ in range(4)]
        base_ip = '.'.join(map(str, octets))
        prefix_len = draw(st.integers(min_value=8, max_value=32))
    else:
        # IPv6 ranges - use simplified format
        groups = [draw(st.integers(min_value=0, max_value=0xFFFF)) for _ in range(4)]
        base_ip = ':'.join(f'{g:x}' for g in groups) + '::'
        prefix_len = draw(st.integers(min_value=16, max_value=128))

    ip_range = f"{base_ip}/{prefix_len}"

    description = draw(
        st.text(
            min_size=1,
            max_size=200,
            alphabet=st.characters(
                whitelist_categories=(
                    'Lu',
                    'Ll',
                    'Nd',
                    'Zs'),
                whitelist_characters='.-_')))

    # Generate valid module names
    valid_modules = [
        "local_info",
        "internet_info",
        "netbox",
        "checkmk",
        "openitcockpit",
        "openvas",
        "infoblox"]
    qualifies_for = draw(
        st.lists(
            st.sampled_from(valid_modules),
            min_size=0,
            max_size=3,
            unique=True))

    rfc_reference = draw(
        st.one_of(
            st.none(),
            st.text(
                min_size=1,
                max_size=50,
                alphabet=st.characters(
                    whitelist_categories=(
                        'Lu',
                        'Ll',
                        'Nd'),
                    whitelist_characters=' -'))))

    return ClassificationRule(
        name=name,
        ip_range=ip_range,
        description=description,
        qualifies_for=qualifies_for,
        rfc_reference=rfc_reference
    )


@composite
def valid_rule_names(draw):
    """Generate valid rule names."""
    return draw(
        st.text(
            min_size=1,
            max_size=50,
            alphabet=st.characters(
                whitelist_categories=(
                    'Lu',
                    'Ll',
                    'Nd'),
                whitelist_characters='_-')))


class TestClassificationCRUDOperations:
    """Property-based tests for classification CRUD operations."""

    @given(valid_classification_rules())
    def test_add_classification_persists_to_json(self, rule):
        """
        Property 12: Classification CRUD Operations (Add)
        For any valid classification rule, adding it should persist the rule to JSON file.
        **Validates: Requirements 6.6**
        """
        # Create temporary config manager
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "config.json"
            classifications_path = Path(temp_dir) / "classifications.json"

            config_manager = ConfigManager(
                config_path=config_path,
                classifications_path=classifications_path
            )

            # Add the classification rule
            try:
                config_manager.add_classification(rule)
            except ValueError:
                assume(False)  # Skip invalid rules

            # Verify it was persisted
            loaded_rules = config_manager.load_classifications()
            assert rule.name in loaded_rules, f"Added rule '{
                rule.name}' should be in loaded classifications"

            loaded_rule = loaded_rules[rule.name]
            assert loaded_rule.name == rule.name, "Rule name should match"
            assert loaded_rule.ip_range == rule.ip_range, "Rule IP range should match"
            assert loaded_rule.description == rule.description, "Rule description should match"
            assert loaded_rule.qualifies_for == rule.qualifies_for, "Rule qualifies_for should match"
            assert loaded_rule.rfc_reference == rule.rfc_reference, "Rule RFC reference should match"

    @given(valid_classification_rules())
    def test_delete_classification_removes_from_json(self, rule):
        """
        Property 12: Classification CRUD Operations (Delete)
        For any classification rule, deleting it should remove it from JSON file.
        **Validates: Requirements 6.6**
        """
        # Create temporary config manager
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "config.json"
            classifications_path = Path(temp_dir) / "classifications.json"

            config_manager = ConfigManager(
                config_path=config_path,
                classifications_path=classifications_path
            )

            # Add the classification rule first
            try:
                config_manager.add_classification(rule)
            except ValueError:
                assume(False)  # Skip invalid rules

            # Verify it exists
            loaded_rules = config_manager.load_classifications()
            assert rule.name in loaded_rules, f"Rule '{
                rule.name}' should exist before deletion"

            # Delete the rule
            result = config_manager.remove_classification(rule.name)
            assert result is True, "Deletion should return True for existing rule"

            # Verify it was removed
            loaded_rules_after = config_manager.load_classifications()
            assert rule.name not in loaded_rules_after, f"Deleted rule '{
                rule.name}' should not be in loaded classifications"

    @given(valid_rule_names())
    def test_delete_nonexistent_classification_returns_false(self, rule_name):
        """
        Property 12: Classification CRUD Operations (Delete Non-existent)
        For any rule name that doesn't exist, deletion should return False.
        **Validates: Requirements 6.6**
        """
        # Create temporary config manager
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "config.json"
            classifications_path = Path(temp_dir) / "classifications.json"

            config_manager = ConfigManager(
                config_path=config_path,
                classifications_path=classifications_path
            )

            # Load existing rules to check if rule_name exists
            existing_rules = config_manager.load_classifications()
            assume(rule_name not in existing_rules)  # Only test with non-existent names

            # Try to delete non-existent rule
            result = config_manager.remove_classification(rule_name)
            assert result is False, f"Deletion of non-existent rule '{rule_name}' should return False"

    @given(valid_classification_rules(), valid_classification_rules())
    def test_update_classification_modifies_json(self, original_rule, updated_rule):
        """
        Property 12: Classification CRUD Operations (Update)
        For any classification rule, updating it should modify the JSON file correctly.
        **Validates: Requirements 6.6**
        """
        # Ensure we're updating to a different rule
        assume(original_rule.name != updated_rule.name or
               original_rule.ip_range != updated_rule.ip_range or
               original_rule.description != updated_rule.description or
               original_rule.qualifies_for != updated_rule.qualifies_for)

        # Create temporary config manager
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "config.json"
            classifications_path = Path(temp_dir) / "classifications.json"

            config_manager = ConfigManager(
                config_path=config_path,
                classifications_path=classifications_path
            )

            # Add the original classification rule
            try:
                config_manager.add_classification(original_rule)
            except ValueError:
                assume(False)  # Skip invalid rules

            # Update the rule
            try:
                result = config_manager.update_classification(
                    original_rule.name, updated_rule)
            except ValueError:
                assume(False)  # Skip invalid updated rules

            assert result is True, "Update should return True for existing rule"

            # Verify the update was persisted
            loaded_rules = config_manager.load_classifications()

            # Original rule name should not exist if name changed
            if original_rule.name != updated_rule.name:
                assert original_rule.name not in loaded_rules, f"Original rule name '{
                    original_rule.name}' should not exist after update"

            # Updated rule should exist
            assert updated_rule.name in loaded_rules, f"Updated rule '{
                updated_rule.name}' should exist"

            loaded_rule = loaded_rules[updated_rule.name]
            assert loaded_rule.name == updated_rule.name, "Updated rule name should match"
            assert loaded_rule.ip_range == updated_rule.ip_range, "Updated rule IP range should match"
            assert loaded_rule.description == updated_rule.description, "Updated rule description should match"
            assert loaded_rule.qualifies_for == updated_rule.qualifies_for, "Updated rule qualifies_for should match"
            assert loaded_rule.rfc_reference == updated_rule.rfc_reference, "Updated rule RFC reference should match"

    @given(valid_rule_names(), valid_classification_rules())
    def test_update_nonexistent_classification_returns_false(
            self, nonexistent_name, updated_rule):
        """
        Property 12: Classification CRUD Operations (Update Non-existent)
        For any rule name that doesn't exist, update should return False.
        **Validates: Requirements 6.6**
        """
        # Create temporary config manager
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "config.json"
            classifications_path = Path(temp_dir) / "classifications.json"

            config_manager = ConfigManager(
                config_path=config_path,
                classifications_path=classifications_path
            )

            # Load existing rules to check if nonexistent_name exists
            existing_rules = config_manager.load_classifications()
            # Only test with non-existent names
            assume(nonexistent_name not in existing_rules)

            # Try to update non-existent rule
            try:
                result = config_manager.update_classification(
                    nonexistent_name, updated_rule)
                assert result is False, f"Update of non-existent rule '{nonexistent_name}' should return False"
            except ValueError:
                assume(False)  # Skip invalid updated rules

    @given(st.lists(valid_classification_rules(), min_size=1,
           max_size=5, unique_by=lambda x: x.name))
    def test_multiple_crud_operations_maintain_consistency(self, rules):
        """
        Property 12: Classification CRUD Operations (Multiple Operations)
        For any sequence of CRUD operations, the JSON file should maintain consistency.
        **Validates: Requirements 6.6**
        """
        # Create temporary config manager
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "config.json"
            classifications_path = Path(temp_dir) / "classifications.json"

            config_manager = ConfigManager(
                config_path=config_path,
                classifications_path=classifications_path
            )

            # Add all rules
            added_rules = []
            for rule in rules:
                try:
                    config_manager.add_classification(rule)
                    added_rules.append(rule)
                except ValueError:
                    continue  # Skip invalid rules

            assume(len(added_rules) > 0)  # Need at least one valid rule

            # Verify all added rules exist
            loaded_rules = config_manager.load_classifications()
            for rule in added_rules:
                assert rule.name in loaded_rules, f"Added rule '{
                    rule.name}' should exist"

            # Delete half of the rules
            rules_to_delete = added_rules[:len(added_rules) // 2]
            for rule in rules_to_delete:
                result = config_manager.remove_classification(rule.name)
                assert result is True, f"Deletion of '{rule.name}' should succeed"

            # Verify deleted rules are gone and remaining rules still exist
            loaded_rules_after_delete = config_manager.load_classifications()
            for rule in rules_to_delete:
                assert rule.name not in loaded_rules_after_delete, f"Deleted rule '{
                    rule.name}' should not exist"

            remaining_rules = added_rules[len(added_rules) // 2:]
            for rule in remaining_rules:
                assert rule.name in loaded_rules_after_delete, f"Remaining rule '{
                    rule.name}' should still exist"
