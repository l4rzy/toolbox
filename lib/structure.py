from typing import Optional, Any, List, Dict, TypeVar, Callable, Type, cast
from enum import Enum

T = TypeVar("T")
EnumT = TypeVar("EnumT", bound=Enum)

def from_str(x: Any) -> str:
    assert isinstance(x, str)
    return x

def from_str_or_none(x: Any) -> str | None:
    assert isinstance(x, str | None)
    return x

def from_bool(x: Any) -> bool:
    assert isinstance(x, bool)
    return x

def from_int(x: Any) -> int:
    assert isinstance(x, int)
    return x

def from_int_or_bool(x: Any) -> int | bool:
    assert isinstance(x, int | bool )
    return x

def from_list(f: Callable[[Any], T], x: Any) -> List[T]:
    assert isinstance(x, list)
    return [f(y) for y in x]

def to_class(c: Type[T], x: Any) -> dict:
    assert isinstance(x, c)
    return cast(Any, x).to_dict()

def from_none(x: Any) -> Any:
    assert x is None
    return x

def from_union(fs, x):
    for f in fs:
        try:
            return f(x)
        except:
            pass
    assert False

def to_enum(c: Type[EnumT], x: Any) -> EnumT:
    assert isinstance(x, c)
    return x.value

def from_float(x: Any) -> float:
    assert isinstance(x, (float, int)) and not isinstance(x, bool)
    return float(x)

def to_float(x: Any) -> float:
    assert isinstance(x, float)
    return x

def from_dict(f: Callable[[Any], T], x: Any) -> Dict[str, T]:
    assert isinstance(x, dict)
    return { k: f(v) for (k, v) in x.items() }


class AbuseObjectData:
    ip_address: str
    is_public: bool
    ip_version: int
    is_whitelisted: bool
    abuse_confidence_score: int
    country_code: str | None
    usage_type: str
    isp: str
    domain: str
    hostnames: List[Any]
    is_tor: bool
    total_reports: int
    num_distinct_users: int
    last_reported_at: str

    def __init__(self, ip_address: str, is_public: bool, ip_version: int, is_whitelisted: bool, abuse_confidence_score: int, country_code: str, usage_type: str, isp: str, domain: str, hostnames: List[Any], is_tor: bool, total_reports: int, num_distinct_users: int, last_reported_at: str) -> None:
        self.ip_address = ip_address
        self.is_public = is_public
        self.ip_version = ip_version
        self.is_whitelisted = is_whitelisted
        self.abuse_confidence_score = abuse_confidence_score
        self.country_code = country_code
        self.usage_type = usage_type
        self.isp = isp
        self.domain = domain
        self.hostnames = hostnames
        self.is_tor = is_tor
        self.total_reports = total_reports
        self.num_distinct_users = num_distinct_users
        self.last_reported_at = last_reported_at

    @staticmethod
    def from_dict(obj: Any) -> 'AbuseObjectData':
        assert isinstance(obj, dict)
        ip_address = from_str(obj.get("ipAddress"))
        is_public = from_bool(obj.get("isPublic"))
        ip_version = from_int(obj.get("ipVersion"))
        is_whitelisted = from_bool(obj.get("isWhitelisted"))
        abuse_confidence_score = from_int(obj.get("abuseConfidenceScore"))
        country_code = from_str_or_none(obj.get("countryCode"))
        usage_type = from_str(obj.get("usageType"))
        isp = from_str(obj.get("isp"))
        domain = from_str_or_none(obj.get("domain"))
        hostnames = from_list(lambda x: x, obj.get("hostnames"))
        is_tor = from_bool(obj.get("isTor"))
        total_reports = from_int(obj.get("totalReports"))
        num_distinct_users = from_int(obj.get("numDistinctUsers"))
        last_reported_at = from_str(obj.get("lastReportedAt"))
        return AbuseObjectData(ip_address, is_public, ip_version, is_whitelisted, abuse_confidence_score, country_code, usage_type, isp, domain, hostnames, is_tor, total_reports, num_distinct_users, last_reported_at)

    def to_dict(self) -> dict:
        result: dict = {}
        result["ipAddress"] = from_str(self.ip_address)
        result["isPublic"] = from_bool(self.is_public)
        result["ipVersion"] = from_int(self.ip_version)
        result["isWhitelisted"] = from_bool(self.is_whitelisted)
        result["abuseConfidenceScore"] = from_int(self.abuse_confidence_score)
        result["countryCode"] = from_str_or_none(self.country_code)
        result["usageType"] = from_str(self.usage_type)
        result["isp"] = from_str(self.isp)
        result["domain"] = from_str_or_none(self.domain)
        result["hostnames"] = from_list(lambda x: x, self.hostnames)
        result["isTor"] = from_bool(self.is_tor)
        result["totalReports"] = from_int(self.total_reports)
        result["numDistinctUsers"] = from_int(self.num_distinct_users)
        result["lastReportedAt"] = from_str(self.last_reported_at)
        return result


class AbuseObject:
    data: AbuseObjectData

    def __init__(self, data: AbuseObjectData) -> None:
        self.data = data

    @staticmethod
    def from_dict(obj: Any) -> 'AbuseObject':
        assert isinstance(obj, dict)
        data = AbuseObjectData.from_dict(obj.get("data"))
        return AbuseObject(data)

    def to_dict(self) -> dict:
        result: dict = {}
        result["data"] = to_class(AbuseObjectData, self.data)
        return result

class Value:
    version: str
    type: str
    name: str
    info: Optional[str]

    def __init__(self, version: str, type: str, name: str, info: Optional[str]) -> None:
        self.version = version
        self.type = type
        self.name = name
        self.info = info

    @staticmethod
    def from_dict(obj: Any) -> 'Value':
        assert isinstance(obj, dict)
        version = from_str(obj.get("version"))
        type = from_str(obj.get("type"))
        name = from_str(obj.get("name"))
        info = from_union([from_str, from_none], obj.get("info"))
        return Value(version, type, name, info)

    def to_dict(self) -> dict:
        result: dict = {}
        result["version"] = from_str(self.version)
        result["type"] = from_str(self.type)
        result["name"] = from_str(self.name)
        result["info"] = from_union([from_str, from_none], self.info)
        return result


class Detectiteasy:
    filetype: str
    values: List[Value]

    def __init__(self, filetype: str, values: List[Value]) -> None:
        self.filetype = filetype
        self.values = values

    @staticmethod
    def from_dict(obj: Any) -> 'Detectiteasy':
        assert isinstance(obj, dict)
        filetype = from_str(obj.get("filetype"))
        values = from_list(Value.from_dict, obj.get("values"))
        return Detectiteasy(filetype, values)

    def to_dict(self) -> dict:
        result: dict = {}
        result["filetype"] = from_str(self.filetype)
        result["values"] = from_list(lambda x: to_class(Value, x), self.values)
        return result


class Category(Enum):
    TYPE_UNSUPPORTED = "type-unsupported"
    UNDETECTED = "undetected"

class Method(Enum):
    BLACKLIST = "blacklist"

class LastAnalysisResult:
    category: Category
    engine_name: str
    engine_version: str
    result: None
    method: Method
    engine_update: int

    def __init__(self, category: Category, engine_name: str, engine_version: str, result: None, method: Method, engine_update: int) -> None:
        self.category = category
        self.engine_name = engine_name
        self.engine_version = engine_version
        self.result = result
        self.method = method
        self.engine_update = engine_update

    @staticmethod
    def from_dict(obj: Any) -> 'LastAnalysisResult':
        assert isinstance(obj, dict)
        category = Category(obj.get("category"))
        engine_name = from_str(obj.get("engine_name"))
        engine_version = from_str(obj.get("engine_version"))
        result = from_none(obj.get("result"))
        method = Method(obj.get("method"))
        engine_update = int(from_str(obj.get("engine_update")))
        return LastAnalysisResult(category, engine_name, engine_version, result, method, engine_update)

    def to_dict(self) -> dict:
        result: dict = {}
        result["category"] = to_enum(Category, self.category)
        result["engine_name"] = from_str(self.engine_name)
        result["engine_version"] = from_str(self.engine_version)
        result["result"] = from_none(self.result)
        result["method"] = to_enum(Method, self.method)
        result["engine_update"] = from_str(str(self.engine_update))
        return result


class LastAnalysisStats:
    harmless: int
    type_unsupported: int
    suspicious: int
    confirmed_timeout: int
    timeout: int
    failure: int
    malicious: int
    undetected: int

    def __init__(self, harmless: int, type_unsupported: int, suspicious: int, confirmed_timeout: int, timeout: int, failure: int, malicious: int, undetected: int) -> None:
        self.harmless = harmless
        self.type_unsupported = type_unsupported
        self.suspicious = suspicious
        self.confirmed_timeout = confirmed_timeout
        self.timeout = timeout
        self.failure = failure
        self.malicious = malicious
        self.undetected = undetected

    @staticmethod
    def from_dict(obj: Any) -> 'LastAnalysisStats':
        assert isinstance(obj, dict)
        harmless = from_int(obj.get("harmless"))
        type_unsupported = from_int(obj.get("type-unsupported"))
        suspicious = from_int(obj.get("suspicious"))
        confirmed_timeout = from_int(obj.get("confirmed-timeout"))
        timeout = from_int(obj.get("timeout"))
        failure = from_int(obj.get("failure"))
        malicious = from_int(obj.get("malicious"))
        undetected = from_int(obj.get("undetected"))
        return LastAnalysisStats(harmless, type_unsupported, suspicious, confirmed_timeout, timeout, failure, malicious, undetected)

    def to_dict(self) -> dict:
        result: dict = {}
        result["harmless"] = from_int(self.harmless)
        result["type-unsupported"] = from_int(self.type_unsupported)
        result["suspicious"] = from_int(self.suspicious)
        result["confirmed-timeout"] = from_int(self.confirmed_timeout)
        result["timeout"] = from_int(self.timeout)
        result["failure"] = from_int(self.failure)
        result["malicious"] = from_int(self.malicious)
        result["undetected"] = from_int(self.undetected)
        return result


class ImportList:
    library_name: str
    imported_functions: List[str]

    def __init__(self, library_name: str, imported_functions: List[str]) -> None:
        self.library_name = library_name
        self.imported_functions = imported_functions

    @staticmethod
    def from_dict(obj: Any) -> 'ImportList':
        assert isinstance(obj, dict)
        library_name = from_str(obj.get("library_name"))
        imported_functions = from_list(from_str, obj.get("imported_functions"))
        return ImportList(library_name, imported_functions)

    def to_dict(self) -> dict:
        result: dict = {}
        result["library_name"] = from_str(self.library_name)
        result["imported_functions"] = from_list(from_str, self.imported_functions)
        return result


class Overlay:
    entropy: float
    offset: int
    chi2: float
    filetype: str
    size: int
    md5: str

    def __init__(self, entropy: float, offset: int, chi2: float, filetype: str, size: int, md5: str) -> None:
        self.entropy = entropy
        self.offset = offset
        self.chi2 = chi2
        self.filetype = filetype
        self.size = size
        self.md5 = md5

    @staticmethod
    def from_dict(obj: Any) -> 'Overlay':
        assert isinstance(obj, dict)
        entropy = from_float(obj.get("entropy"))
        offset = from_int(obj.get("offset"))
        chi2 = from_float(obj.get("chi2"))
        filetype = from_str(obj.get("filetype"))
        size = from_int(obj.get("size"))
        md5 = from_str(obj.get("md5"))
        return Overlay(entropy, offset, chi2, filetype, size, md5)

    def to_dict(self) -> dict:
        result: dict = {}
        result["entropy"] = to_float(self.entropy)
        result["offset"] = from_int(self.offset)
        result["chi2"] = to_float(self.chi2)
        result["filetype"] = from_str(self.filetype)
        result["size"] = from_int(self.size)
        result["md5"] = from_str(self.md5)
        return result


class ResourceDetail:
    lang: str
    entropy: float
    chi2: float
    filetype: str
    sha256: str
    type: str

    def __init__(self, lang: str, entropy: float, chi2: float, filetype: str, sha256: str, type: str) -> None:
        self.lang = lang
        self.entropy = entropy
        self.chi2 = chi2
        self.filetype = filetype
        self.sha256 = sha256
        self.type = type

    @staticmethod
    def from_dict(obj: Any) -> 'ResourceDetail':
        assert isinstance(obj, dict)
        lang = from_str(obj.get("lang"))
        entropy = from_float(obj.get("entropy"))
        chi2 = from_float(obj.get("chi2"))
        filetype = from_str(obj.get("filetype"))
        sha256 = from_str(obj.get("sha256"))
        type = from_str(obj.get("type"))
        return ResourceDetail(lang, entropy, chi2, filetype, sha256, type)

    def to_dict(self) -> dict:
        result: dict = {}
        result["lang"] = from_str(self.lang)
        result["entropy"] = to_float(self.entropy)
        result["chi2"] = to_float(self.chi2)
        result["filetype"] = from_str(self.filetype)
        result["sha256"] = from_str(self.sha256)
        result["type"] = from_str(self.type)
        return result


class ResourceLangs:
    chinese_simplified: int

    def __init__(self, chinese_simplified: int) -> None:
        self.chinese_simplified = chinese_simplified

    @staticmethod
    def from_dict(obj: Any) -> 'ResourceLangs':
        assert isinstance(obj, dict)
        chinese_simplified = from_int(obj.get("CHINESE SIMPLIFIED"))
        return ResourceLangs(chinese_simplified)

    def to_dict(self) -> dict:
        result: dict = {}
        result["CHINESE SIMPLIFIED"] = from_int(self.chinese_simplified)
        return result


class ResourceTypes:
    rt_version: int

    def __init__(self, rt_version: int) -> None:
        self.rt_version = rt_version

    @staticmethod
    def from_dict(obj: Any) -> 'ResourceTypes':
        assert isinstance(obj, dict)
        rt_version = from_int(obj.get("RT_VERSION"))
        return ResourceTypes(rt_version)

    def to_dict(self) -> dict:
        result: dict = {}
        result["RT_VERSION"] = from_int(self.rt_version)
        return result


class Section:
    name: str
    chi2: float
    virtual_address: int
    entropy: float
    raw_size: int
    flags: str
    virtual_size: int
    md5: str

    def __init__(self, name: str, chi2: float, virtual_address: int, entropy: float, raw_size: int, flags: str, virtual_size: int, md5: str) -> None:
        self.name = name
        self.chi2 = chi2
        self.virtual_address = virtual_address
        self.entropy = entropy
        self.raw_size = raw_size
        self.flags = flags
        self.virtual_size = virtual_size
        self.md5 = md5

    @staticmethod
    def from_dict(obj: Any) -> 'Section':
        assert isinstance(obj, dict)
        name = from_str(obj.get("name"))
        chi2 = from_float(obj.get("chi2"))
        virtual_address = from_int(obj.get("virtual_address"))
        entropy = from_float(obj.get("entropy"))
        raw_size = from_int(obj.get("raw_size"))
        flags = from_str(obj.get("flags"))
        virtual_size = from_int(obj.get("virtual_size"))
        md5 = from_str(obj.get("md5"))
        return Section(name, chi2, virtual_address, entropy, raw_size, flags, virtual_size, md5)

    def to_dict(self) -> dict:
        result: dict = {}
        result["name"] = from_str(self.name)
        result["chi2"] = to_float(self.chi2)
        result["virtual_address"] = from_int(self.virtual_address)
        result["entropy"] = to_float(self.entropy)
        result["raw_size"] = from_int(self.raw_size)
        result["flags"] = from_str(self.flags)
        result["virtual_size"] = from_int(self.virtual_size)
        result["md5"] = from_str(self.md5)
        return result


class PEInfo:
    resource_details: List[ResourceDetail]
    rich_pe_header_hash: str
    imphash: str
    overlay: Overlay
    compiler_product_versions: List[str]
    resource_langs: ResourceLangs
    machine_type: int
    timestamp: int
    resource_types: ResourceTypes
    sections: List[Section]
    import_list: List[ImportList]
    entry_point: int

    def __init__(self, resource_details: List[ResourceDetail], rich_pe_header_hash: str, imphash: str, overlay: Overlay, compiler_product_versions: List[str], resource_langs: ResourceLangs, machine_type: int, timestamp: int, resource_types: ResourceTypes, sections: List[Section], import_list: List[ImportList], entry_point: int) -> None:
        self.resource_details = resource_details
        self.rich_pe_header_hash = rich_pe_header_hash
        self.imphash = imphash
        self.overlay = overlay
        self.compiler_product_versions = compiler_product_versions
        self.resource_langs = resource_langs
        self.machine_type = machine_type
        self.timestamp = timestamp
        self.resource_types = resource_types
        self.sections = sections
        self.import_list = import_list
        self.entry_point = entry_point

    @staticmethod
    def from_dict(obj: Any) -> 'PEInfo':
        assert isinstance(obj, dict)
        resource_details = from_list(ResourceDetail.from_dict, obj.get("resource_details"))
        rich_pe_header_hash = from_str(obj.get("rich_pe_header_hash"))
        imphash = from_str(obj.get("imphash"))
        overlay = Overlay.from_dict(obj.get("overlay"))
        compiler_product_versions = from_list(from_str, obj.get("compiler_product_versions"))
        resource_langs = ResourceLangs.from_dict(obj.get("resource_langs"))
        machine_type = from_int(obj.get("machine_type"))
        timestamp = from_int(obj.get("timestamp"))
        resource_types = ResourceTypes.from_dict(obj.get("resource_types"))
        sections = from_list(Section.from_dict, obj.get("sections"))
        import_list = from_list(ImportList.from_dict, obj.get("import_list"))
        entry_point = from_int(obj.get("entry_point"))
        return PEInfo(resource_details, rich_pe_header_hash, imphash, overlay, compiler_product_versions, resource_langs, machine_type, timestamp, resource_types, sections, import_list, entry_point)

    def to_dict(self) -> dict:
        result: dict = {}
        result["resource_details"] = from_list(lambda x: to_class(ResourceDetail, x), self.resource_details)
        result["rich_pe_header_hash"] = from_str(self.rich_pe_header_hash)
        result["imphash"] = from_str(self.imphash)
        result["overlay"] = to_class(Overlay, self.overlay)
        result["compiler_product_versions"] = from_list(from_str, self.compiler_product_versions)
        result["resource_langs"] = to_class(ResourceLangs, self.resource_langs)
        result["machine_type"] = from_int(self.machine_type)
        result["timestamp"] = from_int(self.timestamp)
        result["resource_types"] = to_class(ResourceTypes, self.resource_types)
        result["sections"] = from_list(lambda x: to_class(Section, x), self.sections)
        result["import_list"] = from_list(lambda x: to_class(ImportList, x), self.import_list)
        result["entry_point"] = from_int(self.entry_point)
        return result


class Algorithm(Enum):
    SHA1_RSA = "sha1RSA"
    SHA256_RSA = "sha256RSA"
    SHA384_RSA = "sha384RSA"


class CounterSignersDetail:
    status: Optional[str]
    valid_usage: Optional[str]
    name: str
    algorithm: Algorithm
    valid_from: str
    valid_to: str
    serial_number: str
    cert_issuer: str
    thumbprint: str
    counter_signers_detail_valid_usage: Optional[str]

    def __init__(self, status: Optional[str], valid_usage: Optional[str], name: str, algorithm: Algorithm, valid_from: str, valid_to: str, serial_number: str, cert_issuer: str, thumbprint: str, counter_signers_detail_valid_usage: Optional[str]) -> None:
        self.status = status
        self.valid_usage = valid_usage
        self.name = name
        self.algorithm = algorithm
        self.valid_from = valid_from
        self.valid_to = valid_to
        self.serial_number = serial_number
        self.cert_issuer = cert_issuer
        self.thumbprint = thumbprint
        self.counter_signers_detail_valid_usage = counter_signers_detail_valid_usage

    @staticmethod
    def from_dict(obj: Any) -> 'CounterSignersDetail':
        assert isinstance(obj, dict)
        status = from_union([from_str, from_none], obj.get("status"))
        valid_usage = from_union([from_str, from_none], obj.get("valid usage"))
        name = from_str(obj.get("name"))
        algorithm = Algorithm(obj.get("algorithm"))
        valid_from = from_str(obj.get("valid from"))
        valid_to = from_str(obj.get("valid to"))
        serial_number = from_str(obj.get("serial number"))
        cert_issuer = from_str(obj.get("cert issuer"))
        thumbprint = from_str(obj.get("thumbprint"))
        counter_signers_detail_valid_usage = from_union([from_str, from_none], obj.get("valid_usage"))
        return CounterSignersDetail(status, valid_usage, name, algorithm, valid_from, valid_to, serial_number, cert_issuer, thumbprint, counter_signers_detail_valid_usage)

    def to_dict(self) -> dict:
        result: dict = {}
        result["status"] = from_union([from_str, from_none], self.status)
        result["valid usage"] = from_union([from_str, from_none], self.valid_usage)
        result["name"] = from_str(self.name)
        result["algorithm"] = to_enum(Algorithm, self.algorithm)
        result["valid from"] = from_str(self.valid_from)
        result["valid to"] = from_str(self.valid_to)
        result["serial number"] = from_str(self.serial_number)
        result["cert issuer"] = from_str(self.cert_issuer)
        result["thumbprint"] = from_str(self.thumbprint)
        result["valid_usage"] = from_union([from_str, from_none], self.counter_signers_detail_valid_usage)
        return result


class SignatureInfo:
    product: str
    verified: str
    description: str
    file_version: str
    signing_date: str
    x509: List[CounterSignersDetail]
    original_name: str
    signers: str
    counter_signers_details: List[CounterSignersDetail]
    counter_signers: str
    copyright: str
    signers_details: List[CounterSignersDetail]
    internal_name: str

    def __init__(self, product: str, verified: str, description: str, file_version: str, signing_date: str, x509: List[CounterSignersDetail], original_name: str, signers: str, counter_signers_details: List[CounterSignersDetail], counter_signers: str, copyright: str, signers_details: List[CounterSignersDetail], internal_name: str) -> None:
        self.product = product
        self.verified = verified
        self.description = description
        self.file_version = file_version
        self.signing_date = signing_date
        self.x509 = x509
        self.original_name = original_name
        self.signers = signers
        self.counter_signers_details = counter_signers_details
        self.counter_signers = counter_signers
        self.copyright = copyright
        self.signers_details = signers_details
        self.internal_name = internal_name

    @staticmethod
    def from_dict(obj: Any) -> 'SignatureInfo':
        assert isinstance(obj, dict)
        product = from_str(obj.get("product"))
        verified = from_str(obj.get("verified"))
        description = from_str(obj.get("description"))
        file_version = from_str(obj.get("file version"))
        signing_date = from_str(obj.get("signing date"))
        x509 = from_list(CounterSignersDetail.from_dict, obj.get("x509"))
        original_name = from_str(obj.get("original name"))
        signers = from_str(obj.get("signers"))
        counter_signers_details = from_list(CounterSignersDetail.from_dict, obj.get("counter signers details"))
        counter_signers = from_str(obj.get("counter signers"))
        copyright = from_str(obj.get("copyright"))
        signers_details = from_list(CounterSignersDetail.from_dict, obj.get("signers details"))
        internal_name = from_str(obj.get("internal name"))
        return SignatureInfo(product, verified, description, file_version, signing_date, x509, original_name, signers, counter_signers_details, counter_signers, copyright, signers_details, internal_name)

    def to_dict(self) -> dict:
        result: dict = {}
        result["product"] = from_str(self.product)
        result["verified"] = from_str(self.verified)
        result["description"] = from_str(self.description)
        result["file version"] = from_str(self.file_version)
        result["signing date"] = from_str(self.signing_date)
        result["x509"] = from_list(lambda x: to_class(CounterSignersDetail, x), self.x509)
        result["original name"] = from_str(self.original_name)
        result["signers"] = from_str(self.signers)
        result["counter signers details"] = from_list(lambda x: to_class(CounterSignersDetail, x), self.counter_signers_details)
        result["counter signers"] = from_str(self.counter_signers)
        result["copyright"] = from_str(self.copyright)
        result["signers details"] = from_list(lambda x: to_class(CounterSignersDetail, x), self.signers_details)
        result["internal name"] = from_str(self.internal_name)
        return result


class TotalVotes:
    harmless: int
    malicious: int

    def __init__(self, harmless: int, malicious: int) -> None:
        self.harmless = harmless
        self.malicious = malicious

    @staticmethod
    def from_dict(obj: Any) -> 'TotalVotes':
        assert isinstance(obj, dict)
        harmless = from_int(obj.get("harmless"))
        malicious = from_int(obj.get("malicious"))
        return TotalVotes(harmless, malicious)

    def to_dict(self) -> dict:
        result: dict = {}
        result["harmless"] = from_int(self.harmless)
        result["malicious"] = from_int(self.malicious)
        return result


class Trid:
    file_type: str
    probability: float

    def __init__(self, file_type: str, probability: float) -> None:
        self.file_type = file_type
        self.probability = probability

    @staticmethod
    def from_dict(obj: Any) -> 'Trid':
        assert isinstance(obj, dict)
        file_type = from_str(obj.get("file_type"))
        probability = from_float(obj.get("probability"))
        return Trid(file_type, probability)

    def to_dict(self) -> dict:
        result: dict = {}
        result["file_type"] = from_str(self.file_type)
        result["probability"] = to_float(self.probability)
        return result


class Attributes:
    type_description: str
    tlsh: str
    vhash: str
    type_tags: List[str]
    creation_date: int
    names: List[str]
    signature_info: SignatureInfo
    last_modification_date: int
    type_tag: str
    times_submitted: int
    total_votes: TotalVotes
    size: int
    type_extension: str
    authentihash: str
    detectiteasy: Detectiteasy
    last_submission_date: int
    last_analysis_results: Dict[str, LastAnalysisResult]
    trid: List[Trid]
    sha256: str
    tags: List[str]
    last_analysis_date: int
    unique_sources: int
    first_submission_date: int
    sha1: str
    ssdeep: str
    md5: str
    pe_info: PEInfo
    magic: str
    last_analysis_stats: LastAnalysisStats
    meaningful_name: str
    reputation: int
    first_seen_itw_date: int

    def __init__(self, type_description: str, tlsh: str, vhash: str, type_tags: List[str], creation_date: int, names: List[str], signature_info: SignatureInfo, last_modification_date: int, type_tag: str, times_submitted: int, total_votes: TotalVotes, size: int, type_extension: str, authentihash: str, detectiteasy: Detectiteasy, last_submission_date: int, last_analysis_results: Dict[str, LastAnalysisResult], trid: List[Trid], sha256: str, tags: List[str], last_analysis_date: int, unique_sources: int, first_submission_date: int, sha1: str, ssdeep: str, md5: str, pe_info: PEInfo, magic: str, last_analysis_stats: LastAnalysisStats, meaningful_name: str, reputation: int, first_seen_itw_date: int) -> None:
        self.type_description = type_description
        self.tlsh = tlsh
        self.vhash = vhash
        self.type_tags = type_tags
        self.creation_date = creation_date | None
        self.names = names
        self.signature_info = signature_info
        self.last_modification_date = last_modification_date
        self.type_tag = type_tag
        self.times_submitted = times_submitted
        self.total_votes = total_votes
        self.size = size
        self.type_extension = type_extension
        self.authentihash = authentihash
        self.detectiteasy = detectiteasy
        self.last_submission_date = last_submission_date
        self.last_analysis_results = last_analysis_results
        self.trid = trid
        self.sha256 = sha256
        self.tags = tags
        self.last_analysis_date = last_analysis_date
        self.unique_sources = unique_sources
        self.first_submission_date = first_submission_date
        self.sha1 = sha1
        self.ssdeep = ssdeep
        self.md5 = md5
        self.pe_info = pe_info
        self.magic = magic
        self.last_analysis_stats = last_analysis_stats
        self.meaningful_name = meaningful_name
        self.reputation = reputation
        self.first_seen_itw_date = first_seen_itw_date

    @staticmethod
    def from_dict(obj: Any) -> 'Attributes':
        assert isinstance(obj, dict)
        type_description = from_str(obj.get("type_description"))
        tlsh = from_str(obj.get("tlsh"))
        vhash = from_str(obj.get("vhash"))
        type_tags = from_list(from_str, obj.get("type_tags"))
        creation_date = from_int_or_bool(obj.get("creation_date"))
        names = from_list(from_str, obj.get("names"))
        # signature_info = SignatureInfo.from_dict(obj.get("signature_info"))
        last_modification_date = from_int(obj.get("last_modification_date"))
        type_tag = from_str(obj.get("type_tag"))
        times_submitted = from_int(obj.get("times_submitted"))
        total_votes = TotalVotes.from_dict(obj.get("total_votes"))
        size = from_int(obj.get("size"))
        type_extension = from_str(obj.get("type_extension"))
        # authentihash = from_str(obj.get("authentihash"))
        detectiteasy = Detectiteasy.from_dict(obj.get("detectiteasy"))
        last_submission_date = from_int(obj.get("last_submission_date"))
        last_analysis_results = from_dict(LastAnalysisResult.from_dict, obj.get("last_analysis_results"))
        trid = from_list(Trid.from_dict, obj.get("trid"))
        sha256 = from_str(obj.get("sha256"))
        tags = from_list(from_str, obj.get("tags"))
        last_analysis_date = from_int(obj.get("last_analysis_date"))
        unique_sources = from_int(obj.get("unique_sources"))
        first_submission_date = from_int(obj.get("first_submission_date"))
        sha1 = from_str(obj.get("sha1"))
        ssdeep = from_str(obj.get("ssdeep"))
        md5 = from_str(obj.get("md5"))
        pe_info = PEInfo.from_dict(obj.get("pe_info"))
        magic = from_str(obj.get("magic"))
        last_analysis_stats = LastAnalysisStats.from_dict(obj.get("last_analysis_stats"))
        meaningful_name = from_str(obj.get("meaningful_name"))
        reputation = from_int(obj.get("reputation"))
        first_seen_itw_date = from_int(obj.get("first_seen_itw_date"))
        return Attributes(type_description, tlsh, vhash, type_tags, creation_date, names, signature_info, last_modification_date, type_tag, times_submitted, total_votes, size, type_extension, authentihash, detectiteasy, last_submission_date, last_analysis_results, trid, sha256, tags, last_analysis_date, unique_sources, first_submission_date, sha1, ssdeep, md5, pe_info, magic, last_analysis_stats, meaningful_name, reputation, first_seen_itw_date)

    def to_dict(self) -> dict:
        result: dict = {}
        result["type_description"] = from_str(self.type_description)
        result["tlsh"] = from_str(self.tlsh)
        result["vhash"] = from_str(self.vhash)
        result["type_tags"] = from_list(from_str, self.type_tags)
        result["creation_date"] = from_int(self.creation_date)
        result["names"] = from_list(from_str, self.names)
        result["signature_info"] = to_class(SignatureInfo, self.signature_info)
        result["last_modification_date"] = from_int(self.last_modification_date)
        result["type_tag"] = from_str(self.type_tag)
        result["times_submitted"] = from_int(self.times_submitted)
        result["total_votes"] = to_class(TotalVotes, self.total_votes)
        result["size"] = from_int(self.size)
        result["type_extension"] = from_str(self.type_extension)
        result["authentihash"] = from_str(self.authentihash)
        result["detectiteasy"] = to_class(Detectiteasy, self.detectiteasy)
        result["last_submission_date"] = from_int(self.last_submission_date)
        result["last_analysis_results"] = from_dict(lambda x: to_class(LastAnalysisResult, x), self.last_analysis_results)
        result["trid"] = from_list(lambda x: to_class(Trid, x), self.trid)
        result["sha256"] = from_str(self.sha256)
        result["tags"] = from_list(from_str, self.tags)
        result["last_analysis_date"] = from_int(self.last_analysis_date)
        result["unique_sources"] = from_int(self.unique_sources)
        result["first_submission_date"] = from_int(self.first_submission_date)
        result["sha1"] = from_str(self.sha1)
        result["ssdeep"] = from_str(self.ssdeep)
        result["md5"] = from_str(self.md5)
        result["pe_info"] = to_class(PEInfo, self.pe_info)
        result["magic"] = from_str(self.magic)
        result["last_analysis_stats"] = to_class(LastAnalysisStats, self.last_analysis_stats)
        result["meaningful_name"] = from_str(self.meaningful_name)
        result["reputation"] = from_int(self.reputation)
        result["first_seen_itw_date"] = from_int(self.first_seen_itw_date)
        return result


class Links:
    links_self: str

    def __init__(self, links_self: str) -> None:
        self.links_self = links_self

    @staticmethod
    def from_dict(obj: Any) -> 'Links':
        assert isinstance(obj, dict)
        links_self = from_str(obj.get("self"))
        return Links(links_self)

    def to_dict(self) -> dict:
        result: dict = {}
        result["self"] = from_str(self.links_self)
        return result

class Datum:
    attributes: Attributes
    type: str
    id: str
    links: Links

    def __init__(self, attributes: Attributes, type: str, id: str, links: Links) -> None:
        self.attributes = attributes
        self.type = type
        self.id = id
        self.links = links

    @staticmethod
    def from_dict(obj: Any) -> 'Datum':
        assert isinstance(obj, dict)
        attributes = Attributes.from_dict(obj.get("attributes"))
        type = from_str(obj.get("type"))
        id = from_str(obj.get("id"))
        links = Links.from_dict(obj.get("links"))
        return Datum(attributes, type, id, links)

    def to_dict(self) -> dict:
        result: dict = {}
        result["attributes"] = to_class(Attributes, self.attributes)
        result["type"] = from_str(self.type)
        result["id"] = from_str(self.id)
        result["links"] = to_class(Links, self.links)
        return result

class VirusTotalObject:
    data: List[Datum]
    links: Links

    def __init__(self, data: List[Datum], links: Links) -> None:
        self.data = data
        self.links = links

    @staticmethod
    def from_dict(obj: Any) -> 'VirusTotalObject':
        assert isinstance(obj, dict)
        data = from_list(Datum.from_dict, obj.get("data"))
        links = Links.from_dict(obj.get("links"))
        return VirusTotalObject(data, links)

    def to_dict(self) -> dict:
        result: dict = {}
        result["data"] = from_list(lambda x: to_class(Datum, x), self.data)
        result["links"] = to_class(Links, self.links)
        return result
