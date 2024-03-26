from __future__ import annotations
from enum import Enum

from typing import Any, List, Optional, Dict

from pydantic import BaseModel, Field


class DTSInputSource(Enum):
    USER = 0
    CLIPBOARD = 1
    GENERIC_REPORT = 2
    TEXT_REPORT = 3
    ANALYZER = 4


class DataClass(Enum):
    IPV4ADDR = 0
    IPV6ADDR = 1
    SHA256HASH = 2
    SHA1HASH = 3
    MD5HASH = 4
    BASE64 = 5
    PCOMPUTER = 6
    USER = 7
    DOMAIN = 8
    INTERNALIP = 9


ABUSE_CATEGORIES = (
    "None",
    "DNS Compromise",
    "DNS Poisoning",
    "Fraud Orders",
    "DDoS Attack",
    "FTP Brute-Force",
    "Ping of Death",
    "Phishing",
    "Fraud VoIP",
    "Open Proxy",
    "Web Spam",
    "Email Spam",
    "Blog Spam",
    "VPN IP",
    "Port Scan",
    "Hacking",
    "SQL Injection",
    "Spoofing",
    "Brute-Force",
    "Bad Web Bot",
    "Exploited Host",
    "Web App Attack",
    "SSH",
    "IoT Targeted",
)


class AbuseReport(BaseModel):
    reportedAt: str
    comment: Optional[str] = None
    categories: List[int]
    reporterId: Optional[int]
    reporterCountryCode: Optional[str] = None
    reporterCountryName: Optional[str] = None


class AbuseDataObject(BaseModel):
    ipAddress: str
    isPublic: bool
    ipVersion: int
    isWhitelisted: Any
    abuseConfidenceScore: int
    countryCode: Optional[str]
    usageType: Optional[str]
    isp: Optional[str]
    domain: Optional[str]
    hostnames: List
    isTor: bool
    totalReports: int
    numDistinctUsers: int
    lastReportedAt: Optional[str]
    reports: Optional[List[AbuseReport]] = []


class AbuseObject(BaseModel):
    data: Optional[AbuseDataObject]


class VTLastAnalysisStats(BaseModel):
    harmless: Optional[int] = 0
    type_unsupported: Optional[int] = None  # Field(..., alias="type-unsupported")
    suspicious: Optional[int] = 0
    confirmed_timeout: Optional[int] = None  # Field(..., alias="confirmed-timeout")
    timeout: Optional[int] = 0
    failure: Optional[int] = None
    malicious: Optional[int] = 0
    undetected: Optional[int] = 0


class VTSignatureInfo(BaseModel):
    product: Optional[str] = None
    verified: Optional[str] = None
    description: Optional[str] = None
    file_version: Optional[str] = None
    signing_date: Optional[str] = None
    x509: Optional[list] = None
    signers: Optional[str] = None
    counter_signers_details: Optional[list] = None
    counter_signers: Optional[str] = None
    copyright: Optional[str] = None
    signers_details: Optional[list] = None


class VTAttributes(BaseModel):
    type_description: Optional[str] = None
    tlsh: Optional[str] = None
    vhash: Optional[str] = None
    type_tags: Optional[List[str]] = None
    creation_date: Optional[int] = None
    names: Optional[List[str]] = None
    signature_info: Optional[VTSignatureInfo] = None
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
    last_analysis_date: Optional[int] = None
    unique_sources: Optional[int] = None
    first_submission_date: Optional[int] = None
    sha1: Optional[str] = None
    ssdeep: Optional[str] = None
    md5: Optional[str] = None
    pe_info: Optional[dict] = None
    magic: Optional[str] = None
    last_analysis_stats: Optional[VTLastAnalysisStats] = None
    last_analysis_results: Optional[dict] = None
    reputation: Optional[int] = None
    first_seen_itw_date: Optional[int] = None


class VTLinks(BaseModel):
    self: Optional[str] = None


class VTItem(BaseModel):
    attributes: VTAttributes
    type: Optional[str] = None
    id: Optional[str] = None
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


class NISTDescription(BaseModel):
    lang: Optional[str] = None
    value: Optional[str] = None


class NISTCvssData(BaseModel):
    version: Optional[str] = None
    vectorString: Optional[str] = None
    attackVector: Optional[str] = None
    attackComplexity: Optional[str] = None
    privilegesRequired: Optional[str] = None
    userInteraction: Optional[str] = None
    scope: Optional[str] = None
    confidentialityImpact: Optional[str] = None
    integrityImpact: Optional[str] = None
    availabilityImpact: Optional[str] = None
    baseScore: Optional[float] = None
    baseSeverity: Optional[str] = None


class NISTCvssMetricV31Item(BaseModel):
    source: Optional[str] = None
    type: Optional[str] = None
    cvssData: Optional[NISTCvssData] = None
    exploitabilityScore: Optional[float] = None
    impactScore: Optional[float] = None


class NISTCvssData1(BaseModel):
    version: Optional[str] = None
    vectorString: Optional[str] = None
    accessVector: Optional[str] = None
    accessComplexity: Optional[str] = None
    authentication: Optional[str] = None
    confidentialityImpact: Optional[str] = None
    integrityImpact: Optional[str] = None
    availabilityImpact: Optional[str] = None
    baseScore: Optional[float] = None


class NISTCvssMetricV2Item(BaseModel):
    source: Optional[str] = None
    type: Optional[str] = None
    cvssData: Optional[NISTCvssData1] = None
    baseSeverity: Optional[str] = None
    exploitabilityScore: Optional[float] = None
    impactScore: Optional[float] = None
    acInsufInfo: Optional[bool] = None
    obtainAllPrivilege: Optional[bool] = None
    obtainUserPrivilege: Optional[bool] = None
    obtainOtherPrivilege: Optional[bool] = None
    userInteractionRequired: Optional[bool] = None


class NISTMetrics(BaseModel):
    cvssMetricV31: Optional[List[NISTCvssMetricV31Item]] = None
    cvssMetricV2: Optional[List[NISTCvssMetricV2Item]] = None


class NISTDescriptionItem(NISTDescription):
    pass


class NISTWeakness(BaseModel):
    source: Optional[str] = None
    type: Optional[str] = None
    description: Optional[List[NISTDescriptionItem]] = None


class NISTCpeMatchItem(BaseModel):
    vulnerable: Optional[bool] = None
    criteria: Optional[str] = None
    versionEndIncluding: Optional[str] = None
    matchCriteriaId: Optional[str] = None


class NISTNode(BaseModel):
    operator: Optional[str] = None
    negate: Optional[bool] = None
    cpeMatch: Optional[List[NISTCpeMatchItem]] = None


class NISTConfiguration(BaseModel):
    nodes: Optional[List[NISTNode]] = None


class NISTReference(BaseModel):
    url: Optional[str] = None
    source: Optional[str] = None
    tags: Optional[List[str]] = None


class NISTCve(BaseModel):
    id: Optional[str] = None
    sourceIdentifier: Optional[str] = None
    published: Optional[str] = None
    lastModified: Optional[str] = None
    vulnStatus: Optional[str] = None
    descriptions: Optional[List[NISTDescription]] = None
    metrics: Optional[NISTMetrics] = None
    weaknesses: Optional[List[NISTWeakness]] = None
    configurations: Optional[List[NISTConfiguration]] = None
    references: Optional[List[NISTReference]] = None


class NISTVulnerability(BaseModel):
    cve: Optional[NISTCve] = None


class NISTObject(BaseModel):
    resultsPerPage: Optional[int] = None
    startIndex: Optional[int] = None
    totalResults: Optional[int] = None
    format: Optional[str] = None
    version: Optional[str] = None
    timestamp: Optional[str] = None
    vulnerabilities: Optional[List[NISTVulnerability]] = None


class CirclCVEAccess(BaseModel):
    authentication: Optional[str] = None
    complexity: Optional[str] = None
    vector: Optional[str] = None


class CirclCVEImpact(BaseModel):
    availability: Optional[str] = None
    confidentiality: Optional[str] = None
    integrity: Optional[str] = None


class CirclCVEVulnerableConfigurationItem(BaseModel):
    id: Optional[str] = None
    title: Optional[str] = None


class CirclCVEObject(BaseModel):
    Modified: Optional[str] = None
    Published: Optional[str] = None
    access: Optional[CirclCVEAccess] = None
    assigner: Optional[str] = None
    cvss: Optional[float] = None
    cvss_time: Optional[str] = Field(None, alias="cvss-time")
    cvss_vector: Optional[str] = Field(None, alias="cvss-vector")
    cwe: Optional[str] = None
    id: Optional[str] = None
    impact: Optional[CirclCVEImpact] = None
    last_modified: Optional[str] = Field(None, alias="last-modified")
    summary: Optional[str] = None
    vulnerable_configuration: Optional[List[CirclCVEVulnerableConfigurationItem]] = None
    vulnerable_product: Optional[List[str]] = None
