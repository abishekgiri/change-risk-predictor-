import os
from typing import Optional
from dotenv import load_dotenv

load_dotenv()

def load_private_key() -> Optional[str]:
    """
    Load GitHub App Private Key from file or environment.
    """
    # 1. Try file first (Docker/Local)
    pem_path = os.getenv("GITHUB_PRIVATE_KEY_PATH", "compliancebot-app.pem")
    if os.path.exists(pem_path):
        with open(pem_path, 'r') as f:
            return f.read()
    
    # 2. Try env var (Deployment)
    pem_env = os.getenv("GITHUB_PRIVATE_KEY")
    if pem_env:
        return pem_env
        
    return None

class SaaSConfig:
    APP_ID = os.getenv("GITHUB_APP_ID")
    WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET")
    PRIVATE_KEY = load_private_key()
    
    # Infra
    REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://compliancebot:development_password@127.0.0.1:5433/compliancebot_saas")
    
    @classmethod
    def validate(cls):
        missing = []
        if not cls.APP_ID: missing.append("GITHUB_APP_ID")
        if not cls.WEBHOOK_SECRET: missing.append("GITHUB_WEBHOOK_SECRET")
        if not cls.PRIVATE_KEY: missing.append("compliancebot-app.pem (or GITHUB_PRIVATE_KEY)")
        
        if missing:
            raise ValueError(f"Missing SaaS Configuration: {', '.join(missing)}")

