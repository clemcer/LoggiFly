from pydantic import (
    BaseModel,
    ConfigDict,
)
from typing import Optional
from config.models.base import (
    BaseConfigModel,
    DefaultsConfig,
    NotificationsConfig,
    SettingsConfig,
)
from config.models.docker import ContainerSourceConfig, SwarmSourceConfig


class GlobalConfigV2(BaseConfigModel):
    # model_config = ConfigDict(extra="ignore") 

    # version: Literal[2] = 2 # TODO: force user setting version or not?
    defaults: Optional[DefaultsConfig] = DefaultsConfig()
    containers: Optional[ContainerSourceConfig] = None
    swarm_services: Optional[SwarmSourceConfig] = None
    notifications: Optional[NotificationsConfig] = None
    settings: Optional[SettingsConfig] = SettingsConfig()

