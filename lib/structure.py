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


class TotalVotes(BaseModel):
    harmless: int
    malicious: int


class Values(BaseModel):
    TerminalSessionId: Optional[str] = None
    ProcessGuid: str
    ProcessId: str
    Product: Optional[str] = None
    Description: Optional[str] = None
    Company: Optional[str] = None
    ParentProcessGuid: Optional[str] = None
    User: Optional[str] = None
    Hashes: Optional[str] = None
    OriginalFileName: Optional[str] = None
    ParentImage: Optional[str] = None
    FileVersion: Optional[str] = None
    ParentProcessId: Optional[str] = None
    CurrentDirectory: Optional[str] = None
    CommandLine: Optional[str] = None
    EventID: str
    LogonGuid: Optional[str] = None
    LogonId: Optional[str] = None
    Image: str
    IntegrityLevel: Optional[str] = None
    ParentCommandLine: Optional[str] = None
    UtcTime: str
    RuleName: str
    CreationUtcTime: Optional[str] = None
    TargetFilename: Optional[str] = None


class MatchContextItem(BaseModel):
    values: Values


class SigmaAnalysisResult(BaseModel):
    rule_title: str
    rule_source: str
    match_context: List[MatchContextItem]
    rule_level: str
    rule_id: str
    rule_author: str
    rule_description: str


class Bkav(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class Lionic(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class Elastic(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class DrWeb(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class MicroWorldEScan(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class CMC(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class CATQuickHeal(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class Skyhigh(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class ALYac(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class Malwarebytes(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class VIPRE(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class Sangfor(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class Trustlook(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class BitDefender(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class K7GW(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class K7AntiVirus(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class Arcabit(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class Baidu(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class VirIT(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class SymantecMobileInsight(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class Symantec(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class Tehtris(BaseModel):
    category: str
    engine_name: str
    engine_version: None
    result: None
    method: str
    engine_update: str


class ESETNOD32(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class APEX(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class TrendMicroHouseCall(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class Avast(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class ClamAV(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class Kaspersky(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class Alibaba(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class NANOAntivirus(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class ViRobot(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class Rising(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class Cynet(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class Emsisoft(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class FSecure(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class BitDefenderTheta(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class Zillya(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class TrendMicro(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class SentinelOne(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class Sophos(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class Paloalto(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class GData(BaseModel):
    category: str
    engine_name: str
    engine_version: None
    result: None
    method: str
    engine_update: str


class Jiangmin(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class Webroot(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class Google(BaseModel):
    category: str
    engine_name: str
    engine_version: None
    result: None
    method: str
    engine_update: str


class Avira(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class AntiyAVL(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class Kingsoft(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class Gridinsoft(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class Xcitium(BaseModel):
    category: str
    engine_name: str
    engine_version: None
    result: None
    method: str
    engine_update: str


class Microsoft(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class SUPERAntiSpyware(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class ZoneAlarm(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class AvastMobile(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class Varist(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class BitDefenderFalx(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class AhnLabV3(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class Acronis(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class McAfee(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class TACHYON(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class DeepInstinct(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class VBA32(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class Cylance(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class Zoner(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class Tencent(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class Yandex(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class Ikarus(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class MaxSecure(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class Fortinet(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class AVG(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class Cybereason(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class Panda(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: str


class CrowdStrike(BaseModel):
    category: str
    engine_name: str
    engine_version: str
    result: None
    method: str
    engine_update: None


class LastAnalysisResults(BaseModel):
    Bkav: Bkav
    Lionic: Lionic
    Elastic: Elastic
    DrWeb: DrWeb
    MicroWorld_eScan: MicroWorldEScan = Field(..., alias='MicroWorld-eScan')
    CMC: CMC
    CAT_QuickHeal: CATQuickHeal = Field(..., alias='CAT-QuickHeal')
    Skyhigh: Skyhigh
    ALYac: ALYac
    Malwarebytes: Malwarebytes
    VIPRE: VIPRE
    Sangfor: Sangfor
    Trustlook: Trustlook
    BitDefender: BitDefender
    K7GW: K7GW
    K7AntiVirus: K7AntiVirus
    Arcabit: Arcabit
    Baidu: Baidu
    VirIT: VirIT
    SymantecMobileInsight: SymantecMobileInsight
    Symantec: Symantec
    tehtris: Tehtris
    ESET_NOD32: ESETNOD32 = Field(..., alias='ESET-NOD32')
    APEX: APEX
    TrendMicro_HouseCall: TrendMicroHouseCall = Field(..., alias='TrendMicro-HouseCall')
    Avast: Avast
    ClamAV: ClamAV
    Kaspersky: Kaspersky
    Alibaba: Alibaba
    NANO_Antivirus: NANOAntivirus = Field(..., alias='NANO-Antivirus')
    ViRobot: ViRobot
    Rising: Rising
    Cynet: Cynet
    Emsisoft: Emsisoft
    F_Secure: FSecure = Field(..., alias='F-Secure')
    BitDefenderTheta: BitDefenderTheta
    Zillya: Zillya
    TrendMicro: TrendMicro
    SentinelOne: SentinelOne
    Sophos: Sophos
    Paloalto: Paloalto
    GData: GData
    Jiangmin: Jiangmin
    Webroot: Webroot
    Google: Google
    Avira: Avira
    Antiy_AVL: AntiyAVL = Field(..., alias='Antiy-AVL')
    Kingsoft: Kingsoft
    Gridinsoft: Gridinsoft
    Xcitium: Xcitium
    Microsoft: Microsoft
    SUPERAntiSpyware: SUPERAntiSpyware
    ZoneAlarm: ZoneAlarm
    Avast_Mobile: AvastMobile = Field(..., alias='Avast-Mobile')
    Varist: Varist
    BitDefenderFalx: BitDefenderFalx
    AhnLab_V3: AhnLabV3 = Field(..., alias='AhnLab-V3')
    Acronis: Acronis
    McAfee: McAfee
    TACHYON: TACHYON
    DeepInstinct: DeepInstinct
    VBA32: VBA32
    Cylance: Cylance
    Zoner: Zoner
    Tencent: Tencent
    Yandex: Yandex
    Ikarus: Ikarus
    MaxSecure: MaxSecure
    Fortinet: Fortinet
    AVG: AVG
    Cybereason: Cybereason
    Panda: Panda
    CrowdStrike: CrowdStrike


class TridItem(BaseModel):
    file_type: str
    probability: float


class SigmaIntegratedRuleSetGitHub(BaseModel):
    high: int
    medium: int
    critical: int
    low: int


class SigmaAnalysisSummary(BaseModel):
    Sigma_Integrated_Rule_Set__GitHub_: SigmaIntegratedRuleSetGitHub = Field(
        ..., alias='Sigma Integrated Rule Set (GitHub)'
    )


class ZenboxLinux(BaseModel):
    category: str
    confidence: int
    sandbox_name: str
    malware_classification: List[str]


class SandboxVerdicts(BaseModel):
    Zenbox_Linux: ZenboxLinux = Field(..., alias='Zenbox Linux')


class Extensions(BaseModel):
    exe: int
    lib: int
    zip: int
    h: int
    py: int
    dll: int
    pc: int
    sdb: int
    pyc: int
    pyd: int
    sla: int


class FileTypes(BaseModel):
    directory: int
    unknown: int
    Portable_Executable: int = Field(..., alias='Portable Executable')
    ZIP: int
    XML: int


class BundleInfo(BaseModel):
    highest_datetime: str
    lowest_datetime: str
    num_children: int
    extensions: Extensions
    file_types: FileTypes
    type: str
    uncompressed_size: int


class LastAnalysisStats(BaseModel):
    harmless: int
    type_unsupported: int = Field(..., alias='type-unsupported')
    suspicious: int
    confirmed_timeout: int = Field(..., alias='confirmed-timeout')
    timeout: int
    failure: int
    malicious: int
    undetected: int


class SigmaAnalysisStats(BaseModel):
    high: int
    medium: int
    critical: int
    low: int


class Attributes(BaseModel):
    type_description: str
    tlsh: str
    vhash: str
    type_tags: List[str]
    names: List[str]
    last_modification_date: int
    type_tag: str
    times_submitted: int
    total_votes: TotalVotes
    size: int
    type_extension: str
    last_submission_date: int
    sigma_analysis_results: List[SigmaAnalysisResult]
    last_analysis_results: LastAnalysisResults
    trid: List[TridItem]
    sigma_analysis_summary: SigmaAnalysisSummary
    sandbox_verdicts: SandboxVerdicts
    sha256: str
    tags: List[str]
    last_analysis_date: int
    unique_sources: int
    first_submission_date: int
    ssdeep: str
    bundle_info: BundleInfo
    md5: str
    sha1: str
    magic: str
    last_analysis_stats: LastAnalysisStats
    meaningful_name: str
    reputation: int
    sigma_analysis_stats: SigmaAnalysisStats


class Links(BaseModel):
    self: str


class Datum(BaseModel):
    attributes: Attributes
    type: str
    id: str
    links: Links


class VirusTotalObject(BaseModel):
    data: List[Datum]
    links: Links
