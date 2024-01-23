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
    harmless: int
    type_unsupported: int = Field(..., alias="type-unsupported")
    suspicious: int
    confirmed_timeout: int = Field(..., alias="confirmed-timeout")
    timeout: int
    failure: int
    malicious: int
    undetected: int


class VTAttributes(BaseModel):
    type_description: str
    tlsh: str
    vhash: str
    type_tags: List[str]
    creation_date: int
    names: List[str]
    signature_info: dict
    last_modification_date: int
    type_tag: str
    times_submitted: int
    total_votes: dict
    size: int
    type_extension: str
    authentihash: str
    detectiteasy: dict
    last_submission_date: int
    meaningful_name: str
    trid: List[dict]
    sandbox_verdicts: dict
    sha256: str
    tags: List[str]
    last_analysis_date: int
    unique_sources: int
    first_submission_date: int
    sha1: str
    ssdeep: str
    md5: str
    pe_info: dict
    magic: str
    last_analysis_stats: VTLastAnalysisStats
    last_analysis_results: dict
    reputation: int
    first_seen_itw_date: int


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
    field_shodan: ShodanField = Field(..., alias='_shodan')
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
