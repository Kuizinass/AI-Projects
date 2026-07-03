"""
Token acquisition via Azure Managed Identity (production) or
Service Principal env vars (local dev). No credentials are stored in code.
"""

from azure.identity.aio import (
    DefaultAzureCredential,
    ChainedTokenCredential,
    ManagedIdentityCredential,
    EnvironmentCredential,
)
from msgraph import GraphServiceClient
from src.config.settings import settings

# Scopes
GRAPH_SCOPES = ["https://graph.microsoft.com/.default"]
AZURE_MGMT_SCOPES = ["https://management.azure.com/.default"]
LOG_ANALYTICS_SCOPES = ["https://api.loganalytics.io/.default"]


def get_credential() -> DefaultAzureCredential:
    """
    Returns an async credential. Chain:
      1. Managed Identity (Azure Container Apps / prod)
      2. Environment (local dev via AZURE_CLIENT_ID + AZURE_CLIENT_SECRET)
    """
    return DefaultAzureCredential()


def get_graph_client() -> GraphServiceClient:
    credential = get_credential()
    return GraphServiceClient(credential, scopes=GRAPH_SCOPES)


async def get_azure_token(scope: str) -> str:
    """Raw token for SDKs that need a string (e.g. REST calls)."""
    credential = get_credential()
    token = await credential.get_token(scope)
    return token.token
