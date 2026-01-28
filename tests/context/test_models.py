import pytest
import datetime
from datetime import timezone
import os
import yaml
from releasegate.context.types import EvaluationContext, Actor, Change, Timing
from releasegate.context.builder import ContextBuilder

# Fixture for temporary config
@pytest.fixture
def mock_config(tmp_path):
    config_data = {
        "actors": {
            "default_role": "Junior",
            "github_to_role": {
                "admin_user": "Admin"
            }
        }
    }
    path = tmp_path / "config.yaml"
    with open(path, "w") as f:
        yaml.dump(config_data, f)
    return str(path)

def test_context_validation():
    """Test that Context requires all fields."""
    with pytest.raises(ValueError):
        Actor(role="Dev", team="Infra") # Missing user_id/login

    actor = Actor(user_id="u1", login="u1", role="Dev", team="Infra")
    change = Change(repository="o/r", change_id="1", change_type="PR", files=["a.py"])
    timing = Timing()
    
    ctx = EvaluationContext(actor=actor, change=change, timing=timing)
    assert ctx.environment == "UNKNOWN" # Default
    assert ctx.timing.change_window == "OPEN"
    assert ctx.context_id is not None # UUID generated

def test_context_builder_config(mock_config):
    """Test builder maps roles from config."""
    # Test Admin mapping
    ctx = (ContextBuilder(config_path=mock_config)
           .with_actor(user_id="100", login="admin_user")
           .with_change(repo="acme/api", change_id="1", files=["x.py"], change_type="PR")
           .build())
    assert ctx.actor.role == "Admin"

    # Test Default mapping
    ctx = (ContextBuilder(config_path=mock_config)
           .with_actor(user_id="101", login="unknown_user")
           .with_change(repo="acme/api", change_id="2", files=["x.py"], change_type="PR")
           .build())
    assert ctx.actor.role == "Junior"

def test_builder_auto_actor_from_change(mock_config):
    """Test inferring actor from change author."""
    ctx = (ContextBuilder(config_path=mock_config)
           .with_change(
               repo="acme/api", 
               change_id="1", 
               files=[], 
               change_type="PR",
               author_login="admin_user"
            )
           .build())
    
    assert ctx.actor.login == "admin_user"
    assert ctx.actor.role == "Admin"

def test_builder_environment_override():
    ctx = (ContextBuilder()
           .with_actor(user_id="u", login="l", role="R")
           .with_change(repo="r", change_id="1", files=[], change_type="PR")
           .with_environment("STAGING")
           .build())
    assert ctx.environment == "STAGING"

    # Test default is UNKNOWN
    ctx2 = (ContextBuilder()
           .with_actor(user_id="u", login="l", role="R")
           .with_change(repo="r", change_id="1", files=[], change_type="PR")
           .build())
    assert ctx2.environment == "UNKNOWN"
