from __future__ import annotations

from typing import Any, List, Optional, Dict

from pydantic import BaseModel, Field


class AbuseDataObject(BaseModel):
    ipAddress: str
    isPublic: bool
    ipVersion: int
    isWhitelisted: Any
    abuseConfidenceScore: int
    countryCode: Optional[str]
    usageType: Optional[str]
    isp: str
    domain: Optional[str]
    hostnames: List
    isTor: bool
    totalReports: int
    numDistinctUsers: int
    lastReportedAt: Optional[str]


class AbuseObject(BaseModel):
    data: AbuseDataObject


# ==============================#


class VTLastAnalysisStats(BaseModel):
    harmless: int = 0
    type_unsupported: Optional[int] = None  # Field(..., alias="type-unsupported")
    suspicious: int = 0
    confirmed_timeout: Optional[int] = None  # Field(..., alias="confirmed-timeout")
    timeout: int = 0
    failure: Optional[int] = None
    malicious: int = 0
    undetected: int = 0


class VTAttributes(BaseModel):
    type_description: Optional[str] = None
    tlsh: Optional[str] = None
    vhash: Optional[str] = None
    type_tags: Optional[List[str]] = None
    creation_date: Optional[int] = None
    names: Optional[List[str]] = None
    signature_info: Optional[dict] = None
    last_modification_date: Optional[int] = None
    type_tag: Optional[str] = None
    times_submitted: Optional[int] = None
    total_votes: Optional[dict] = None
    size: Optional[int] = None
    type_extension: Optional[str] = None
    authentihash: Optional[str] = None
    detectiteasy: Optional[dict] = None
    last_submission_date: Optional[int] = None
    meaningful_name: Optional[str] = None
    trid: Optional[List[dict]] = None
    sandbox_verdicts: Optional[dict] = None
    sha256: Optional[str] = None
    tags: Optional[List[str]] = None
    last_analysis_date: int
    unique_sources: Optional[int] = None
    first_submission_date: Optional[int] = None
    sha1: Optional[str] = None
    ssdeep: Optional[str] = None
    md5: Optional[str] = None
    pe_info: Optional[dict] = None
    magic: Optional[str] = None
    last_analysis_stats: VTLastAnalysisStats
    last_analysis_results: dict
    reputation: Optional[int] = None
    first_seen_itw_date: Optional[int] = None


class VTLinks(BaseModel):
    self: str


class VTItem(BaseModel):
    attributes: VTAttributes
    type: str
    id: str
    links: VTLinks


class VirusTotalObject(BaseModel):
    data: List[VTItem]
    links: VTLinks


class ShodanField(BaseModel):
    id: str
    options: Dict[str, Any]
    ptr: bool
    module: str
    crawler: str


class ShodanOpts(BaseModel):
    raw: str


class ShodanLocation(BaseModel):
    city: Optional[str] = None
    region_code: Optional[str] = None
    area_code: Optional[str] = None
    longitude: float
    country_code3: Optional[str] = None
    country_name: str
    postal_code: Optional[str] = None
    dma_code: Optional[str] = None
    country_code: str
    latitude: float


class ShodanDns(BaseModel):
    resolver_hostname: Optional[str] = None
    recursive: bool
    resolver_id: Optional[str] = None
    software: Optional[str] = None


class ShodanItem(BaseModel):
    field_shodan: ShodanField = Field(..., alias="_shodan")
    hash: int
    os: Optional[str] = None
    opts: ShodanOpts
    ip: int
    isp: str
    port: int
    hostnames: List[str]
    location: ShodanLocation
    dns: ShodanDns
    timestamp: str
    domains: List[str]
    org: str
    data: str
    asn: str
    transport: str
    ip_str: str


class ShodanObject(BaseModel):
    region_code: Optional[str] = None
    ip: int
    postal_code: Optional[str] = None
    country_code: str
    city: Optional[str] = None
    dma_code: Optional[str] = None
    last_update: str
    latitude: float
    tags: List
    area_code: Optional[str] = None
    country_name: str
    hostnames: List[str]
    org: str
    data: List[ShodanItem]
    asn: str
    isp: str
    longitude: float
    country_code3: Optional[str] = None
    domains: List[str]
    ip_str: str
    os: Optional[str] = None
    ports: List[int]
