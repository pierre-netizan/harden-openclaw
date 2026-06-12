"""配置加载测试"""
import os
import tempfile
import pytest

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


@pytest.mark.skipif(not HAS_YAML, reason="pyyaml not installed")
class TestConfigLoading:
    @pytest.fixture
    def config_content(self):
        return """
        ollama:
          host: "http://localhost:11434"
          target_model: "qwen3-0.6b"
          prompt_model: "Qwen/Qwen3-4B-Instruct-2507"

        hooks:
          llm01_prompt_injection:
            enabled: true
            action: block
            severity: critical
            patterns:
              - "ignore"
              - "jailbreak"
        """

    def test_load_config_from_file(self, config_content):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(config_content)
            tmp_path = f.name

        try:
            from src.arsguard import load_config
            config = load_config(tmp_path)
            assert config["ollama"]["target_model"] == "qwen3-0.6b"
            assert config["ollama"]["prompt_model"] == "Qwen/Qwen3-4B-Instruct-2507"
            assert "llm01_prompt_injection" in config["hooks"]
        finally:
            os.unlink(tmp_path)

    def test_load_default_config_when_no_file(self):
        from src.arsguard import load_config
        config = load_config("/nonexistent/path/config.yaml")
        assert config["enabled"] is True
        assert config["ollama"]["target_model"] == "qwen3-0.6b"

    def test_environment_variable_config(self, config_content):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(config_content)
            tmp_path = f.name

        try:
            os.environ["ARSGUARD_CONFIG"] = tmp_path
            from src.arsguard import load_config
            config = load_config()
            assert config["ollama"]["target_model"] == "qwen3-0.6b"
        finally:
            os.unlink(tmp_path)
            del os.environ["ARSGUARD_CONFIG"]

    def test_create_plugin_from_config(self, config_content):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(config_content)
            tmp_path = f.name

        try:
            from src.arsguard import create_plugin
            plugin = create_plugin(tmp_path)
            assert plugin.name == "arsguard"
            assert plugin.enabled is True
        finally:
            os.unlink(tmp_path)
