from enum import Enum
import re
from .config import DTSConfig
import ipaddress
import validators

# stolen from https://ihateregex.io/expr/ip/
IPV4ADDR = r"\b((25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3})\b"
IPV6ADDR = r"\b([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\b"
IPV6ADDR2 = r"\b(?!^(?:(?:.*(?:::.*::|:::).*)|::|[0:]+[01]|.*[^:]:|[0-9a-fA-F](?:.*:.*){8}[0-9a-fA-F]|(?:[0-9a-fA-F]:){1,6}[0-9a-fA-F])$)^(?:(::|[0-9a-fA-F]{1,4}:{1,2})([0-9a-fA-F]{1,4}:{1,2}){0,6}([0-9a-fA-F]{1,4}|::)?)\b"

SHA256HASH = r"\b([a-fA-F0-9]{64})\b"
SHA1HASH = r"\b([a-fA-F0-9]{40})\b"
MD5HASH = r"\b([a-fA-F0-9]{32})\b"

PCOMPUTER = r"((GOMC|gomc)\-[0-9]{7})"

URL = r"(https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*))"

BASE64 = (
    r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$"
)


# todo: switch to enum instead of strings
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


class DTSAnalyzer:
    def __init__(self, config: DTSConfig = None):
        self.config = config

        self.lastText = ""
        self.text = ""

        self.insertable = False
        self.hasResult = False
        self.isComplex = False
        self.total = 0

        self.categorizers = {}
        self.categorizers["ipv4"] = re.compile(IPV4ADDR)
        self.categorizers["ipv6"] = re.compile(IPV6ADDR2)
        self.categorizers["sha256"] = re.compile(SHA256HASH)
        self.categorizers["sha1"] = re.compile(SHA1HASH)
        self.categorizers["md5"] = re.compile(MD5HASH)
        self.categorizers["pcomputer"] = re.compile(PCOMPUTER)

        self.dataClass = {}

    def reset(self):
        self.text = ""
        self.insertable = False
        self.hasResult = False
        self.isComplex = False
        self.dataClass = {}

    def process(self, text):
        self.reset()
        if text == self.lastText:
            return

        if len(text) > self.config.get_clipboard_max_length():
            print("[analyzer] clipboard content too big, skipping")
            return

        print(f"[analyzer] analyzing `{text}`")
        self.text = text
        self.insertable = True
        self.total = 0
        for type in self.categorizers:
            print(type)
            occurences = re.finditer(self.categorizers[type], self.text)
            occurences = [o[0] for o in occurences]
            print(occurences)
            if occurences != []:
                self.total += len(occurences)
                self.dataClass[type] = occurences
        self.lastText = text

        if self.total > 1:
            self.isComplex = True
            print(f"[analyzer] complex input: {self.dataClass}")

    def truefalse(self, fn, **kwargs) -> bool:
        try:
            return fn(self.text, **kwargs)
        except Exception:
            return False

    def has_result(self):
        return self.hasResult

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
        return any(item in self.dataClass for item in ["base64"])

    def is_user(self):
        return any(item in self.dataClass for item in ["user"])

    def is_pcomputer(self):
        return any(item in self.dataClass for item in ["pcomputer"])

    def is_url(self):
        return self.truefalse(validators.url) or self.truefalse(validators.domain)

    def is_internal_ip(self):
        return self.is_ip() and ipaddress.ip_address(self.text).is_private is True
