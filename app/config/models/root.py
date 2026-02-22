from pydantic import (
    BaseModel,
    ConfigDict,
    field_validator,
    Field,
)
from typing import Optional, Literal
from config.models.base import (
    BaseConfigModel,
    RootDefaultsConfig,
    NotificationsConfig,
    SettingsConfig,
)
from config.models.docker import ContainerSourceConfig, SwarmSourceConfig


class GlobalConfig(BaseConfigModel):
    """Root configuration model for LoggiFly."""
    version: Literal[2] = Field(2, description="Config schema version. Must be `2`.")
    containers: Optional[ContainerSourceConfig] = Field(None, description="Configuration for Docker container monitoring.")
    swarm: Optional[SwarmSourceConfig] = Field(None, description="Configuration for Docker Swarm service monitoring.")
    notifications: NotificationsConfig = Field(NotificationsConfig(), description="Notification service configuration (ntfy, apprise, webhook).")  # type: ignore[call-arg]
    defaults: RootDefaultsConfig = Field(RootDefaultsConfig(), description="Global default settings applied to all rules unless overridden.")  # type: ignore[call-arg]
    settings: SettingsConfig = Field(SettingsConfig(), description="Application-wide settings.")  # type: ignore[call-arg]

    @field_validator("version", mode="before")
    def ensure_int_literal(cls, v):
        if isinstance(v, int):
            return v
        if isinstance(v, str) and v.isdigit():
            return int(v)
        raise ValueError("Version must be an integer or a string that can be converted to an integer")
