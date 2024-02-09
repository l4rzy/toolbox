import re
from .config import DTSConfig
import ipaddress
import validators
from .structure import DTSInputSource

# stolen from https://ihateregex.io/expr/ip/
IPV4ADDR = r"\b((25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3})\b"
# IPV4ADDR2 = r"\b(?<![0-9])(?:(?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5]))(?![0-9])\b"
IPV6ADDR = r"\b([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\b"
# IPV6ADDR2 = r"\b((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\b"

EMAIL = r"\b[\w\-\.]+@([\w\-]+\.)+[\w\-]{2,6}\b"

SHA256HASH = r"\b([a-fA-F0-9]{64})\b"
SHA224HASH = r"\b([a-fA-F0-9]{57})\b"
SHA1HASH = r"\b([a-fA-F0-9]{40})\b"
MD5HASH = r"\b([a-fA-F0-9]{32})\b"

CVE = r"\b((CVE|cve)-\d{4}-\d{4,7})\b"
# MACADDR = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")

PCOMPUTER = r"((GOMC|gomc)\-[0-9]{7})"

URL = r"(https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*))"

BASE64 = re.compile(
    r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$"
)


class DTSAnalyzer:
    def __init__(self, config: DTSConfig = None):
        self.config = config

        self.lastText = ""
        self.reset()

        self.categorizers = {}
        self.categorizers["ipv4"] = re.compile(IPV4ADDR)
        self.categorizers["ipv6"] = re.compile(IPV6ADDR)
        self.categorizers["sha256"] = re.compile(SHA256HASH)
        self.categorizers["sha224"] = re.compile(SHA224HASH)
        self.categorizers["sha1"] = re.compile(SHA1HASH)
        self.categorizers["md5"] = re.compile(MD5HASH)
        self.categorizers["email"] = re.compile(EMAIL)
        self.categorizers["cve"] = re.compile(CVE)
        self.categorizers["url"] = re.compile(URL)
        self.categorizers["pcomputer"] = re.compile(PCOMPUTER)

    def reset(self):
        self.source = ""
        self.text = ""
        self.content = ""
        self.total = 0
        self.insertable = False
        self.isComplex = False
        self.correction = True
        self.skipped = False
        self.dataClass = {}

    def process(self, source, text):
        if len(text) > self.config.get_clipboard_max_length():
            print("[analyzer] clipboard content too big, skipping")
            return

        # user can override lastText check
        if text == self.lastText and source not in (
            DTSInputSource.USER,
            DTSInputSource.GENERIC_REPORT,
            DTSInputSource.TEXT_REPORT,
        ):
            self.skipped = True
            return

        self.source = source
        self.lastText = text
        # from user button in generic report, no need to do further analysis
        if source == DTSInputSource.GENERIC_REPORT:
            self.reset()
            self.correction = False
            self.text = text
            self.content = text
            self.insertable = True
            return

        if source == DTSInputSource.TEXT_REPORT:
            self.correction = False

        print(f"[analyzer] analyzing `{text}`")
        self.reset()
        self.text = text
        self.total = 0
        lastOne = ""
        for type in self.categorizers:
            occurences = re.finditer(self.categorizers[type], self.text)
            occurences = [o[0] for o in occurences]
            if occurences != []:
                lastOne = occurences[0]
                self.total += len(occurences)
                self.dataClass[type] = occurences

        if self.total > 1:
            self.isComplex = True
            print(f"[analyzer] complex input: {self.dataClass}")
        elif self.total == 1:
            self.content = lastOne
            self.insertable = True
        else:
            self.content = self.text

    def truefalse(self, fn, **kwargs) -> bool:
        try:
            return fn(self.content, **kwargs)
        except Exception:
            return False

    def has_result(self):
        return self.hasResult

    def has_complex_data(self):
        if self.isComplex or self.text != self.content:
            return True
        return False

    def is_ip(self) -> bool:
        return self.truefalse(validators.ipv4, cidr=False) or self.truefalse(
            validators.ipv6, cidr=False
        )

    def is_hash(self) -> bool:
        return (
            self.truefalse(validators.md5)
            or self.truefalse(validators.sha1)
            or self.truefalse(validators.sha256)
            or self.truefalse(validators.sha224)
        )

    def is_mac(self) -> bool:
        return self.truefalse(validators.mac_address)

    def is_base64(self):
        return BASE64.match(self.text)

    def is_cve(self):
        return any(item in self.dataClass for item in ["cve"]) or self.categorizers[
            "cve"
        ].match(self.text)

    def is_user(self):
        return any(item in self.dataClass for item in ["user"])

    def is_pcomputer(self):
        return any(
            item in self.dataClass for item in ["pcomputer"]
        ) or self.categorizers["pcomputer"].match(self.text)

    def is_url(self):
        return self.truefalse(validators.url) or self.truefalse(validators.domain)

    def is_internal_ip(self):
        return self.is_ip() and ipaddress.ip_address(self.content).is_private is True

    # should be called after all other checks
    def is_ocr_result(self):
        return True if self.source == "ocr" else False
