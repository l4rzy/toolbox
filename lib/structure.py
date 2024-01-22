from __future__ import annotations

from typing import Any, List, Optional

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
