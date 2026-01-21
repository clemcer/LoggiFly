from pydantic import (
    BaseModel,
    ConfigDict,
)
from typing import Optional, Literal
from config.models.base import (
    BaseConfigModel,
    RootDefaultsConfig,
    NotificationsConfig,
    SettingsConfig,
)
from config.models.docker import ContainerSourceConfig, SwarmSourceConfig


class GlobalConfigV2(BaseConfigModel):
    # model_config = ConfigDict(extra="ignore") 

    version: Literal[2] = 2 # TODO: force user setting version or not?
    defaults: Optional[RootDefaultsConfig] = RootDefaultsConfig()
    containers: Optional[ContainerSourceConfig] = None
    swarm_services: Optional[SwarmSourceConfig] = None
    notifications: Optional[NotificationsConfig] = None
    settings: Optional[SettingsConfig] = SettingsConfig()

