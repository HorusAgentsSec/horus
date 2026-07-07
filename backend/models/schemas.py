from pydantic import BaseModel, field_validator
from typing import Optional


class AssetCreate(BaseModel):
    name: str
    host: str
    port: Optional[int] = None
    type: str
    is_internal: bool = False
    tags: list[str] = []
    metadata: dict = {}


class AssetUpdate(BaseModel):
    name: Optional[str] = None
    host: Optional[str] = None
    port: Optional[int] = None
    type: Optional[str] = None
    is_internal: Optional[bool] = None
    is_active: Optional[bool] = None
    tags: Optional[list[str]] = None
    metadata: Optional[dict] = None


class ScanCreate(BaseModel):
    asset_id: str
    tools: list[str] = ["nuclei", "nmap"]


class ScanAllRequest(BaseModel):
    tools: list[str] = ["nuclei", "nmap"]


class FindingStatusUpdate(BaseModel):
    status: str


class PermissionPolicyCreate(BaseModel):
    name: str
    description: Optional[str] = None
    scope: str
    scope_value: Optional[str] = None
    rules: list[dict]
    is_active: bool = True

    @field_validator("name")
    @classmethod
    def name_not_blank(cls, v: str) -> str:
        v = (v or "").strip()
        if not v:
            raise ValueError("name is required")
        return v


class PermissionPolicyUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    scope: Optional[str] = None
    scope_value: Optional[str] = None
    rules: Optional[list[dict]] = None
    is_active: Optional[bool] = None

    @field_validator("name")
    @classmethod
    def name_not_blank(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        v = v.strip()
        if not v:
            raise ValueError("name cannot be blank")
        return v


class ScheduleCreate(BaseModel):
    name: str
    asset_ids: list[str]
    cron_expression: str = "0 2 * * *"
    tools: list[str] = ["nuclei", "nmap"]
    enabled: bool = True


class ScheduleUpdate(BaseModel):
    name: Optional[str] = None
    asset_ids: Optional[list[str]] = None
    cron_expression: Optional[str] = None
    tools: Optional[list[str]] = None
    enabled: Optional[bool] = None


class IntegrationCreate(BaseModel):
    type: str  # "slack" | "email"
    # Slack: {"webhook_url": "...", "min_severity": "high"}
    # Email: {"to": ["a@b.com"], "min_severity": "high", optional SMTP overrides}
    config: dict
    enabled: bool = True


class IntegrationUpdate(BaseModel):
    config: Optional[dict] = None
    enabled: Optional[bool] = None


class DiscoverySourceCreate(BaseModel):
    kind: str = "domain"  # "domain" | "network"
    domain: Optional[str] = None          # required when kind == "domain"
    network_cidr: Optional[str] = None    # required when kind == "network"
    cron_expression: Optional[str] = None  # null = manual-only
    auto_create_assets: bool = True
    enabled: bool = True


class DiscoverySourceUpdate(BaseModel):
    domain: Optional[str] = None
    network_cidr: Optional[str] = None
    cron_expression: Optional[str] = None
    auto_create_assets: Optional[bool] = None
    enabled: Optional[bool] = None
