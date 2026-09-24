from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from enum import Enum
from datetime import datetime


class Platform(str, Enum):
    FORTIMANAGER = "fortimanager"
    PALOALTO = "paloalto"


class Severity(str, Enum):
    ACIL = "acil"
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Finding(BaseModel):
    id: str
    platform: Platform
    device_name: str
    customer: str
    rule_id: str
    rule_name: str
    severity: Severity
    check_name: str
    description: str
    recommendation: str
    rule_details: Dict[str, Any]
    detected_at: datetime


class ScanResult(BaseModel):
    device_id: str
    device_name: str
    device_label: str = ""   # Kullanıcı dostu cihaz ismi (ör. "FortiManager-Istanbul")
    device_host: str = ""    # Cihaz IP adresi (ör. "172.30.33.31")
    platform: Platform
    customer: str
    total_rules: int
    findings: List[Finding]
    scanned_at: datetime
