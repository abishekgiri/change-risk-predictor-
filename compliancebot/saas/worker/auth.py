from github import GithubIntegration
from compliancebot.saas.config import SaaSConfig
import time

def get_installation_token(installation_id: int) -> str:
    """
    Generate a short-lived access token for a specific installation
    using the App's Private Key.
    """
    private_key = SaaSConfig.PRIVATE_KEY
    if not private_key:
        raise ValueError("GitHub Private Key not configured")
        
    app_id = SaaSConfig.APP_ID
    
    # PyGithub handles JWT generation and token exchange
    integration = GithubIntegration(app_id, private_key)
    
    token_obj = integration.get_access_token(installation_id)
    return token_obj.token

def get_github_client(installation_id: int):
    """
    Get an authenticated Github client for the installation.
    """
    from github import Github
    token = get_installation_token(installation_id)
    return Github(token)
