from pydantic import (
    field_validator,
    model_validator,
)
from typing import Literal, Optional, List, ClassVar
from constants import MonitorType, SUPPORTED_CONTAINER_EVENTS, SUPPORTED_CONTAINER_ACTIONS
from config.models.base import (
    BaseConfigModel,
    OliveTinAction,
    KeywordBase,
    DefaultsConfig,
)
from config.helpers import (
    validate_and_filter_olivetin_actions,
    validate_container_events,
    generate_id_for_policies,
    validate_shorthand_or_match,
)


# ================================================
# Shared between Container and Swarm
# ================================================

class ScopeConfig(BaseConfigModel):
    hosts: Optional[List[str]] = None


class ContainerEventConfig(DefaultsConfig):
    event: Literal[*SUPPORTED_CONTAINER_EVENTS] # type: ignore
    container_action: Optional[str] = None
    olivetin_actions: Optional[List[OliveTinAction]] = None

    @field_validator("container_action")
    def validate_container_action(cls, v):
        """Validate container action against available actions enum."""
        if v and v.split('@')[0] not in SUPPORTED_CONTAINER_ACTIONS:
            raise ValueError(f"Error in config in field 'container_events': Invalid container action ('{v}'). Must be one of {SUPPORTED_CONTAINER_ACTIONS}")
        return v    
    
    @model_validator(mode="before")
    def validate_olivetin(cls, data: dict) -> dict:
        if data and isinstance(data, dict):
            return validate_and_filter_olivetin_actions(data)
        return data


class ContainerEventBase(BaseConfigModel):
    _MONITOR_TYPE: ClassVar[MonitorType] = MonitorType.CONTAINER

    container_events: Optional[List[ContainerEventConfig]] = None

    @model_validator(mode="before")
    def validate_container_events(cls, data: dict) -> dict:
        """
        Validate container events and container actions.
        container_actions are validated here because the cls._MONITOR_TYPE variable from the parent class is used.
        """
        if "container_events" in data and isinstance(data["container_events"], list):
            data["container_events"] = validate_container_events(data["container_events"], cls._MONITOR_TYPE)
        return data


class PolicyBase(KeywordBase, ContainerEventBase, DefaultsConfig):
    id: Optional[str] = None # TODO: auto-generated if missing
    enabled: bool = True
    scope: Optional[ScopeConfig] = None


# ================================================
# Container Config Models
# ================================================

class ContainerNeverMonitor(BaseConfigModel):
    container_names: Optional[List[str]] = None


class ContainerMatchCriteria(BaseConfigModel):
    container_names: Optional[List[str]] = None


class ContainerMatch(BaseConfigModel):
    include: Optional[ContainerMatchCriteria] = None
    exclude: Optional[ContainerMatchCriteria] = None


class ContainerPolicy(PolicyBase):

    _MONITOR_TYPE: ClassVar[MonitorType] = MonitorType.CONTAINER
    
    container_name: Optional[str] = None # shorthand
    match: Optional[ContainerMatch] = None

    @model_validator(mode="before")                                   
    def validate_shorthand_or_match(cls, data: dict) -> dict:         
        return validate_shorthand_or_match(data, ["container_name"], "match")
        
    # TODO: convert shorthand to match?

class ContainerSourceConfig(KeywordBase, ContainerEventBase):

    _MONITOR_TYPE: ClassVar[MonitorType] = MonitorType.CONTAINER

    scope: Optional[ScopeConfig] = None
    never_monitor: Optional[ContainerNeverMonitor] = None
    defaults: Optional[DefaultsConfig] = None
    policies: Optional[List[ContainerPolicy]] = None
    overlays: Optional[List[ContainerPolicy]] = None

    @model_validator(mode="before")
    def generate_ids_if_missing(cls, data: dict) -> dict:
        return generate_id_for_policies(data)


# ================================================
# Swarm Config Models
# ================================================

class SwarmNeverMonitor(BaseConfigModel):
    stack_names: Optional[List[str]] = None
    service_names: Optional[List[str]] = None

class SwarmMatchCriteria(BaseConfigModel):
    stack_names: Optional[List[str]] = None
    service_names: Optional[List[str]] = None

class SwarmMatch(BaseConfigModel):
    include: Optional[SwarmMatchCriteria] = None
    exclude: Optional[SwarmMatchCriteria] = None

class SwarmPolicy(PolicyBase):

    _MONITOR_TYPE: ClassVar[MonitorType] = MonitorType.SWARM

    stack_name: Optional[str] = None # shorthand
    service_name: Optional[str] = None # shorthand
    match: Optional[SwarmMatch] = None

    @model_validator(mode="before")                                   
    def validate_shorthand_or_match(cls, data: dict) -> dict:         
        return validate_shorthand_or_match(data, ["stack_name", "service_name"], "match")


class SwarmSourceConfig(KeywordBase, ContainerEventBase):

    _MONITOR_TYPE: ClassVar[MonitorType] = MonitorType.SWARM

    scope: Optional[ScopeConfig] = None
    never_monitor: Optional[SwarmNeverMonitor] = None
    defaults: Optional[DefaultsConfig] = None
    policies: Optional[List[SwarmPolicy]] = None
    overlays: Optional[List[SwarmPolicy]] = None

    @model_validator(mode="before")
    def generate_ids_if_missing(cls, data: dict) -> dict:
        return generate_id_for_policies(data)
