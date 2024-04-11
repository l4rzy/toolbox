import re
import ipaddress
import validators

from .config import DTSConfig
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

PCOMPUTER = r"\b([0-9]{7})\b"

URL = r"\b(https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*))\b"

BASE64 = re.compile(
    r"\b(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})\b"
)


class DTSAnalyzer:
    """
    The DTSAnalyzer class is responsible for analyzing and processing text input in the DTS Toolbox.

    Attributes:
        config (DTSConfig): The configuration object for the analyzer.
        lastText (str): The last processed text.
        source (str): The source of the input.
        text (str): The input text to be analyzed.
        content (str): The processed content after analysis.
        total (int): The total number of occurrences found in the text.
        insertable (bool): Indicates whether the content can be inserted.
        isComplex (bool): Indicates whether the input is complex.
        correction (bool): Indicates whether the analyzer is performing a correction.
        skipped (bool): Indicates whether the analysis was skipped.
        message (str): The message associated with the analysis.
        dataClass (dict): A dictionary containing the categorized data.

    Methods:
        __init__(self, config=None): Initializes a new instance of the DTSAnalyzer class.
        reset(self): Resets the analyzer's attributes to their default values.
        process(self, source, text): Processes the input text and performs the analysis.
        truefalse(self, fn, **kwargs) -> bool: Executes a validation function and returns the result.
        has_result(self): Checks if the analyzer has a result.
        has_complex_data(self): Checks if the input has complex data.
        is_ip(self) -> bool: Checks if the input is an IP address.
        is_hash(self) -> bool: Checks if the input is a hash value.
        is_mac(self) -> bool: Checks if the input is a MAC address.
        is_base64(self): Checks if the input is in Base64 format.
        is_cve(self): Checks if the input is a CVE identifier.
        is_user(self): Checks if the input is a user identifier.
        is_pcomputer(self): Checks if the input is a computer identifier.
        is_url(self): Checks if the input is a URL or domain.
        is_internal_ip(self): Checks if the input is an internal IP address.
        is_ocr_result(self): Checks if the input is an OCR result.
    """

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
        """
        Resets the analyzer's attributes to their default values.
        """
        self.source = ""
        self.text = ""
        self.content = ""
        self.total = 0
        self.insertable = False
        self.isComplex = False
        self.correction = True
        self.skipped = False
        self.message = ""
        self.dataClass = {}

    def process(self, source, text):
        """
        Processes the input text and performs the analysis.

        Args:
            source (str): The source of the input.
            text (str): The input text to be analyzed.
        """
        # text report can bypass max length check
        if (
            source != DTSInputSource.TEXT_REPORT
            and len(text) > self.config.get_clipboard_max_length()
        ):
            print("[analyzer] clipboard content too big, skipping")
            self.skipped = True
            self.message = "Content too big!"
            return

        # user can override lastText check
        if text == self.lastText and source not in (
            DTSInputSource.USER,
            DTSInputSource.GENERIC_REPORT,
            DTSInputSource.TEXT_REPORT,
        ):
            self.skipped = True
            self.message = "Nothing new!"
            return

        if text == "":
            self.skipped = True
            self.message = "Empty input!"
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

        print(f"[analyzer] analyzing `{text[:30]}...`")
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
        """
        Executes a validation function and returns the result.

        Args:
            fn (function): The validation function to be executed.
            **kwargs: Additional keyword arguments to be passed to the validation function.

        Returns:
            bool: The result of the validation function.
        """
        try:
            return fn(self.content, **kwargs)
        except Exception as e:
            print(f"[validators] error: {e}")
            return False

    def has_result(self):
        """
        Checks if the analyzer has a result.

        Returns:
            bool: True if the analyzer has a result, False otherwise.
        """
        return self.hasResult

    def has_complex_data(self):
        """
        Checks if the input has complex data.

        Returns:
            bool: True if the input has complex data, False otherwise.
        """
        if self.isComplex or self.text != self.content:
            return True
        return False

    def is_ip(self) -> bool:
        """
        Checks if the input is an IP address.

        Returns:
            bool: True if the input is an IP address, False otherwise.
        """
        return self.truefalse(validators.ipv4, cidr=False) or self.truefalse(
            validators.ipv6, cidr=False
        )

    def is_hash(self) -> bool:
        """
        Checks if the input is a hash value.

        Returns:
            bool: True if the input is a hash value, False otherwise.
        """
        return (
            self.truefalse(validators.md5)
            or self.truefalse(validators.sha1)
            or self.truefalse(validators.sha256)
            or self.truefalse(validators.sha224)
        )

    def is_mac(self) -> bool:
        """
        Checks if the input is a MAC address.

        Returns:
            bool: True if the input is a MAC address, False otherwise.
        """
        return self.truefalse(validators.mac_address)

    def is_base64(self):
        """
        Checks if the input is in Base64 format.

        Returns:
            bool: True if the input is in Base64 format, False otherwise.
        """
        return BASE64.match(self.text)

    def is_cve(self):
        """
        Checks if the input is a CVE identifier.

        Returns:
            bool: True if the input is a CVE identifier, False otherwise.
        """
        return any(item in self.dataClass for item in ["cve"]) or self.categorizers[
            "cve"
        ].match(self.text)

    def is_user(self):
        """
        Checks if the input is a user identifier.

        Returns:
            bool: True if the input is a user identifier, False otherwise.
        """
        return any(item in self.dataClass for item in ["user"])

    def is_pcomputer(self):
        """
        Checks if the input is a computer identifier.

        Returns:
            bool: True if the input is a computer identifier, False otherwise.
        """
        return any(
            item in self.dataClass for item in ["pcomputer"]
        ) or self.categorizers["pcomputer"].match(self.text)

    def is_url(self):
        """
        Checks if the input is a URL or domain.

        Returns:
            bool: True if the input is a URL or domain, False otherwise.
        """
        return self.truefalse(validators.url) or self.truefalse(validators.domain)

    def is_internal_ip(self):
        """
        Checks if the input is an internal IP address.

        Returns:
            bool: True if the input is an internal IP address, False otherwise.
        """
        return self.is_ip() and ipaddress.ip_address(self.content).is_private is True

    def is_ocr_result(self):
        """
        Checks if the input is an OCR result.

        Returns:
            bool: True if the input is an OCR result, False otherwise.
        """
        return True if self.source == "ocr" else False
