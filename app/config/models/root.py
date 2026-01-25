from pydantic import (
    BaseModel,
    ConfigDict,
    field_validator,
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
    version: Literal[2] = 2
    containers: Optional[ContainerSourceConfig] = None
    swarm: Optional[SwarmSourceConfig] = None
    notifications: NotificationsConfig = NotificationsConfig()
    defaults: RootDefaultsConfig = RootDefaultsConfig()
    settings: SettingsConfig = SettingsConfig()
    
    @field_validator("version", mode="before")
    def ensure_int_literal(cls, v):
        if isinstance(v, int):
            return v
        if isinstance(v, str) and v.isdigit():
            return int(v)
        raise ValueError("Version must be an integer or a string that can be converted to an integer")
