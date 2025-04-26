import pytest
from config import Config
from unittest.mock import MagicMock

@pytest.fixture
def mock_es():
    es = MagicMock()
    es.indices.validate_query.return_value = {'valid': True}
    return es

def test_yaml_loading(mock_es):
    config = Config(client=mock_es, rules_folder='examples')
    valid_rules = config.configure_app_rules()
    assert len(valid_rules) == 1  # Assuming 1 valid test rule

def test_invalid_query(mock_es):
    mock_es.indices.validate_query.side_effect = Exception("Invalid query")
    config = Config(client=mock_es, rules_folder='tests/invalid_rules')
    assert len(config.configure_app_rules()) == 0

def test_template_rendering():
    from alerts import ElasticAlerts
    alert = {'reason': '<script>Test</script>', 'status': 'active'}
    ea = ElasticAlerts(message_template="{{ alert.reason }}")
    rendered = ea._render_template(alert)
    assert '&lt;script&gt;' in rendered  # Verify autoescaping