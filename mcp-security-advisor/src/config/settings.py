from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    # Azure tenant
    azure_tenant_id: str = Field(..., env="AZURE_TENANT_ID")
    azure_subscription_id: str = Field(..., env="AZURE_SUBSCRIPTION_ID")

    # Local dev only — omit in production (Managed Identity takes over)
    azure_client_id: str | None = Field(None, env="AZURE_CLIENT_ID")
    azure_client_secret: str | None = Field(None, env="AZURE_CLIENT_SECRET")

    # Sentinel
    sentinel_workspace_id: str = Field(..., env="SENTINEL_WORKSPACE_ID")
    sentinel_workspace_name: str = Field(..., env="SENTINEL_WORKSPACE_NAME")
    sentinel_resource_group: str = Field(..., env="SENTINEL_RESOURCE_GROUP")

    # Escalation
    teams_webhook_url: str = Field(..., env="TEAMS_WEBHOOK_URL")
    teams_callback_base_url: str = Field("", env="TEAMS_CALLBACK_BASE_URL")

    # Risk thresholds
    low_risk_max: int = Field(30, env="LOW_RISK_MAX")
    medium_risk_max: int = Field(70, env="MEDIUM_RISK_MAX")
    high_risk_max: int = Field(90, env="HIGH_RISK_MAX")

    # Observability
    applicationinsights_connection_string: str | None = Field(
        None, env="APPLICATIONINSIGHTS_CONNECTION_STRING"
    )

    # Server
    mcp_server_port: int = Field(8080, env="MCP_SERVER_PORT")
    log_level: str = Field("INFO", env="LOG_LEVEL")

    model_config = {"env_file": ".env", "extra": "ignore"}


settings = Settings()
