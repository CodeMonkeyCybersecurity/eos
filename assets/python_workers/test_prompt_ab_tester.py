#!/usr/bin/env python3
"""
Test suite for the A/B testing prompt selection system
"""

import unittest
import json
import tempfile
import os
import hashlib
from unittest.mock import patch, MagicMock
import sys

# Add the current directory to the path so we can import prompt-ab-tester
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import the classes we want to test
# Note: Since prompt-ab-tester.py has hyphens, we need to import it differently
import importlib.util
spec = importlib.util.spec_from_file_location("prompt_ab_tester", 
                                             os.path.join(os.path.dirname(__file__), "prompt-ab-tester.py"))
prompt_ab_tester = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prompt_ab_tester)

ABTestManager = prompt_ab_tester.ABTestManager
ABTestExperiment = prompt_ab_tester.ABTestExperiment


class TestABTestExperiment(unittest.TestCase):
    """Test the ABTestExperiment class"""
    
    def setUp(self):
        self.test_config = {
            "name": "test_experiment",
            "description": "Test experiment for unit testing",
            "enabled": True,
            "variants": [
                {
                    "name": "control",
                    "weight": 0.5,
                    "prompt_file": "control_prompt.txt"
                },
                {
                    "name": "variant_a",
                    "weight": 0.3,
                    "prompt_file": "variant_a_prompt.txt"
                },
                {
                    "name": "variant_b",
                    "weight": 0.2,
                    "prompt_file": "variant_b_prompt.txt"
                }
            ],
            "sticky_sessions": True,
            "metrics_collection": True
        }
        
    def test_experiment_initialization(self):
        """Test that experiment initializes correctly"""
        experiment = ABTestExperiment(self.test_config)
        
        self.assertEqual(experiment.name, "test_experiment")
        self.assertEqual(experiment.description, "Test experiment for unit testing")
        self.assertTrue(experiment.enabled)
        self.assertTrue(experiment.sticky_sessions)
        self.assertTrue(experiment.metrics_collection)
        self.assertEqual(len(experiment.variants), 3)
        
    def test_variant_weights_sum_to_one(self):
        """Test that variant weights sum to approximately 1.0"""
        experiment = ABTestExperiment(self.test_config)
        total_weight = sum(variant['weight'] for variant in experiment.variants)
        self.assertAlmostEqual(total_weight, 1.0, places=2)
        
    def test_experiment_with_invalid_weights(self):
        """Test experiment with weights that don't sum to 1.0"""
        invalid_config = self.test_config.copy()
        invalid_config['variants'] = [
            {"name": "control", "weight": 0.3, "prompt_file": "control.txt"},
            {"name": "variant", "weight": 0.3, "prompt_file": "variant.txt"}
        ]
        
        experiment = ABTestExperiment(invalid_config)
        total_weight = sum(variant['weight'] for variant in experiment.variants)
        self.assertNotAlmostEqual(total_weight, 1.0, places=2)
        
    def test_disabled_experiment(self):
        """Test disabled experiment handling"""
        disabled_config = self.test_config.copy()
        disabled_config['enabled'] = False
        
        experiment = ABTestExperiment(disabled_config)
        self.assertFalse(experiment.enabled)


class TestABTestManager(unittest.TestCase):
    """Test the ABTestManager class"""
    
    def setUp(self):
        # Create a temporary config file
        self.temp_config_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
        self.config_data = {
            "experiment": {
                "name": "prompt_effectiveness_test",
                "description": "Testing different prompt variants for alert effectiveness",
                "enabled": True,
                "variants": [
                    {
                        "name": "control",
                        "weight": 0.4,
                        "prompt_file": "system_prompt_default.txt"
                    },
                    {
                        "name": "enhanced",
                        "weight": 0.4,
                        "prompt_file": "system_prompt_enhanced.txt"
                    },
                    {
                        "name": "experimental",
                        "weight": 0.2,
                        "prompt_file": "system_prompt_experimental.txt"
                    }
                ],
                "sticky_sessions": True,
                "metrics_collection": True
            },
            "database": {
                "host": "localhost",
                "port": 5432,
                "name": "wazuh",
                "user": "test_user",
                "password": "test_pass"
            }
        }
        
        json.dump(self.config_data, self.temp_config_file)
        self.temp_config_file.close()
        
        # Create temporary prompt files
        self.temp_prompt_dir = tempfile.mkdtemp()
        self.prompt_files = {}
        
        for variant in self.config_data['experiment']['variants']:
            prompt_path = os.path.join(self.temp_prompt_dir, variant['prompt_file'])
            with open(prompt_path, 'w') as f:
                f.write(f"Test prompt content for {variant['name']} variant")
            self.prompt_files[variant['name']] = prompt_path
            
    def tearDown(self):
        # Clean up temporary files
        os.unlink(self.temp_config_file.name)
        for prompt_file in self.prompt_files.values():
            if os.path.exists(prompt_file):
                os.unlink(prompt_file)
        os.rmdir(self.temp_prompt_dir)
        
    def test_manager_initialization(self):
        """Test that ABTestManager initializes correctly"""
        with patch('prompt_ab_tester.ABTestManager._load_prompts'):
            manager = ABTestManager(self.temp_config_file.name)
            
            self.assertIsInstance(manager.experiment, ABTestExperiment)
            self.assertEqual(manager.experiment.name, "prompt_effectiveness_test")
            self.assertTrue(manager.experiment.enabled)
            
    def test_cohort_id_generation(self):
        """Test cohort ID generation for consistent assignment"""
        with patch('prompt_ab_tester.ABTestManager._load_prompts'):
            manager = ABTestManager(self.temp_config_file.name)
            
            alert_data = {
                "agent_id": "test_agent_123",
                "rule_id": "test_rule_456"
            }
            
            cohort_id = manager.get_user_cohort_id(alert_data)
            
            # Test that cohort ID is consistent
            cohort_id2 = manager.get_user_cohort_id(alert_data)
            self.assertEqual(cohort_id, cohort_id2)
            
            # Test that different agent_id produces different cohort
            alert_data2 = {
                "agent_id": "different_agent",
                "rule_id": "test_rule_456"
            }
            cohort_id3 = manager.get_user_cohort_id(alert_data2)
            self.assertNotEqual(cohort_id, cohort_id3)
            
    def test_cohort_id_hashing(self):
        """Test that cohort ID is properly hashed"""
        with patch('prompt_ab_tester.ABTestManager._load_prompts'):
            manager = ABTestManager(self.temp_config_file.name)
            
            alert_data = {
                "agent_id": "test_agent",
                "rule_id": "test_rule"
            }
            
            cohort_id = manager.get_user_cohort_id(alert_data)
            
            # Verify it's a hash-like string
            self.assertIsInstance(cohort_id, str)
            self.assertGreater(len(cohort_id), 10)  # Should be a reasonable hash length
            
            # Verify reproducibility
            expected_hash = hashlib.md5(f"test_agent:test_rule".encode()).hexdigest()[:16]
            self.assertEqual(cohort_id, expected_hash)
            
    def test_variant_selection_distribution(self):
        """Test that variant selection follows weight distribution"""
        with patch('prompt_ab_tester.ABTestManager._load_prompts'):
            manager = ABTestManager(self.temp_config_file.name)
            
            # Mock random to test deterministic selection
            selections = {"control": 0, "enhanced": 0, "experimental": 0}
            
            # Test many selections to verify distribution
            import random
            random.seed(42)  # For reproducible tests
            
            for i in range(1000):
                # Create unique alert data to avoid sticky sessions
                alert_data = {
                    "agent_id": f"agent_{i}",
                    "rule_id": f"rule_{i}"
                }
                
                variant_name, _ = manager.select_prompt_variant(alert_data)
                if variant_name in selections:
                    selections[variant_name] += 1
                    
            total_selections = sum(selections.values())
            self.assertGreater(total_selections, 0)
            
            # Check that distribution roughly matches weights (with some tolerance)
            if total_selections > 0:
                control_ratio = selections["control"] / total_selections
                enhanced_ratio = selections["enhanced"] / total_selections
                experimental_ratio = selections["experimental"] / total_selections
                
                # Allow 10% tolerance due to randomness
                self.assertAlmostEqual(control_ratio, 0.4, delta=0.1)
                self.assertAlmostEqual(enhanced_ratio, 0.4, delta=0.1)
                self.assertAlmostEqual(experimental_ratio, 0.2, delta=0.1)
                
    def test_sticky_sessions(self):
        """Test that sticky sessions work correctly"""
        with patch('prompt_ab_tester.ABTestManager._load_prompts'):
            manager = ABTestManager(self.temp_config_file.name)
            
            alert_data = {
                "agent_id": "test_agent",
                "rule_id": "test_rule"
            }
            
            # First selection
            variant1, prompt1 = manager.select_prompt_variant(alert_data)
            
            # Second selection with same agent/rule should be the same
            variant2, prompt2 = manager.select_prompt_variant(alert_data)
            
            self.assertEqual(variant1, variant2)
            self.assertEqual(prompt1, prompt2)
            
    def test_metrics_collection(self):
        """Test metrics collection functionality"""
        with patch('prompt_ab_tester.ABTestManager._load_prompts'):
            manager = ABTestManager(self.temp_config_file.name)
            
            # Mock database connection
            with patch.object(manager, 'db_connection') as mock_db:
                mock_cursor = MagicMock()
                mock_db.cursor.return_value = mock_cursor
                
                alert_data = {
                    "agent_id": "test_agent",
                    "rule_id": "test_rule",
                    "timestamp": "2024-01-01T12:00:00Z"
                }
                
                variant_name, prompt_content = manager.select_prompt_variant(alert_data)
                
                # Record metrics
                manager.record_metrics(alert_data, variant_name, prompt_content)
                
                # Verify database interaction
                mock_cursor.execute.assert_called()
                mock_db.commit.assert_called()
                
    def test_disabled_experiment(self):
        """Test behavior when experiment is disabled"""
        disabled_config = self.config_data.copy()
        disabled_config['experiment']['enabled'] = False
        
        disabled_config_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
        json.dump(disabled_config, disabled_config_file)
        disabled_config_file.close()
        
        try:
            with patch('prompt_ab_tester.ABTestManager._load_prompts'):
                manager = ABTestManager(disabled_config_file.name)
                
                alert_data = {
                    "agent_id": "test_agent",
                    "rule_id": "test_rule"
                }
                
                # Should fall back to default behavior
                variant_name, prompt_content = manager.select_prompt_variant(alert_data)
                
                # When disabled, should return control variant or handle gracefully
                self.assertIsNotNone(variant_name)
                self.assertIsNotNone(prompt_content)
                
        finally:
            os.unlink(disabled_config_file.name)
            
    def test_missing_prompt_file(self):
        """Test handling of missing prompt files"""
        with patch('prompt_ab_tester.ABTestManager._load_prompts') as mock_load:
            # Simulate missing prompt file
            mock_load.side_effect = FileNotFoundError("Prompt file not found")
            
            with self.assertRaises(FileNotFoundError):
                ABTestManager(self.temp_config_file.name)
                
    def test_invalid_config_file(self):
        """Test handling of invalid config file"""
        invalid_config_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
        invalid_config_file.write("invalid json content")
        invalid_config_file.close()
        
        try:
            with self.assertRaises(json.JSONDecodeError):
                ABTestManager(invalid_config_file.name)
        finally:
            os.unlink(invalid_config_file.name)
            
    def test_variant_selection_edge_cases(self):
        """Test variant selection edge cases"""
        with patch('prompt_ab_tester.ABTestManager._load_prompts'):
            manager = ABTestManager(self.temp_config_file.name)
            
            # Test with missing agent_id
            alert_data = {"rule_id": "test_rule"}
            variant_name, prompt_content = manager.select_prompt_variant(alert_data)
            self.assertIsNotNone(variant_name)
            self.assertIsNotNone(prompt_content)
            
            # Test with missing rule_id
            alert_data = {"agent_id": "test_agent"}
            variant_name, prompt_content = manager.select_prompt_variant(alert_data)
            self.assertIsNotNone(variant_name)
            self.assertIsNotNone(prompt_content)
            
            # Test with empty alert_data
            alert_data = {}
            variant_name, prompt_content = manager.select_prompt_variant(alert_data)
            self.assertIsNotNone(variant_name)
            self.assertIsNotNone(prompt_content)


class TestPromptSelection(unittest.TestCase):
    """Test prompt selection algorithms"""
    
    def test_weighted_selection_algorithm(self):
        """Test the weighted random selection algorithm"""
        weights = [0.4, 0.4, 0.2]
        variants = ["control", "enhanced", "experimental"]
        
        # Test that weights are normalized
        total_weight = sum(weights)
        normalized_weights = [w / total_weight for w in weights]
        self.assertAlmostEqual(sum(normalized_weights), 1.0, places=5)
        
        # Test cumulative distribution
        cumulative = []
        cumsum = 0
        for weight in normalized_weights:
            cumsum += weight
            cumulative.append(cumsum)
            
        self.assertAlmostEqual(cumulative[-1], 1.0, places=5)
        self.assertEqual(len(cumulative), len(variants))
        
    def test_hash_distribution(self):
        """Test that hash-based selection provides good distribution"""
        selections = {"0": 0, "1": 0, "2": 0}
        
        for i in range(1000):
            hash_value = hashlib.md5(f"test_{i}".encode()).hexdigest()
            # Use last digit for simple distribution test
            bucket = str(int(hash_value[-1], 16) % 3)
            selections[bucket] += 1
            
        total = sum(selections.values())
        
        # Each bucket should get roughly 1/3 of selections
        for count in selections.values():
            ratio = count / total
            self.assertGreater(ratio, 0.2)  # At least 20%
            self.assertLess(ratio, 0.5)     # At most 50%


if __name__ == '__main__':
    unittest.main()