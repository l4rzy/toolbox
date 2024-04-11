import io
import json
import threading
import pycurl
from .util import resource_path
from .structure import (
    AbuseObject,
    VirusTotalObject,
    ShodanObject,
    NISTObject,
    CirclCVEObject,
)
import ouilookup
import ipaddress
import csv
from functools import cache
from enum import Enum
import socket


class TunnelService(str, Enum):
    ABUSEIPDB = "abuseipdb"
    VIRUSTOTAL = "virustotal"
    CIRCLCVE = "circl"
    SHODAN = "shodan"
    LOCALIP = "localip"


class CmdWrapper:
    """
    A class that wraps command-line execution functionality.

    Args:
        exe (str): The path to the executable file.

    Attributes:
        exe (str): The path to the executable file.
        process (subprocess.Popen): The subprocess that represents the running command.

    Methods:
        thread_fn(id, cmdline, callback): Executes the command in a separate thread and calls the callback function with the output.
        thread_fn_pipe(id, cmdline, callback): Executes the command in a separate thread with stdout redirected to a pipe and calls the callback function with the output.
        query(id, args): Executes the command with the specified arguments and runs the callback function with the output.
        force_quit(): Terminates the running command forcefully.
    """

    def __init__(self, exe=""):
        self.exe = exe
        self.process = None

    def thread_fn(self, id, cmdline, callback):
        """
        Executes the command in a separate thread and calls the callback function with the output.

        Args:
            id (int): The ID of the command.
            cmdline (list): The command-line arguments.
            callback (function): The callback function to be called with the output.
        """
        import uuid
        import os
        import subprocess
        from pathlib import Path

        Path("./tmp").mkdir(exist_ok=True)
        # use temp file due to subprocess stdout = PIPE blocks itself
        ftempName = f"tmp/{uuid.uuid4()}.bin"
        ftemp = open(ftempName, "w+")
        self.process = subprocess.Popen(cmdline, stdout=ftemp, stderr=None)
        self.process.wait(timeout=10)
        ftemp.close()
        with open(ftempName, "r") as f:
            output = f.read()
        self.process.terminate()
        if os.path.exists(ftempName):
            os.remove(ftempName)

        callback(id, output)

    def thread_fn_pipe(self, id, cmdline, callback):
        """
        Executes the command in a separate thread with stdout redirected to a pipe and calls the callback function with the output.

        Args:
            id (int): The ID of the command.
            cmdline (list): The command-line arguments.
            callback (function): The callback function to be called with the output.
        """
        import subprocess

        self.process = subprocess.Popen(cmdline, stdout=subprocess.PIPE, stderr=None)
        # while self.process.poll() is None:
        #    time.sleep(0.05)
        self.process.wait(timeout=5)
        output, _ = self.process.communicate()
        callback(id, output)

    def query(self, id, args):
        """
        Executes the command with the specified arguments and runs the callback function with the output.

        Args:
            id (int): The ID of the command.
            args (str): The command-line arguments.
        """
        cmdline = [self.exe, args]

        print(f"[worker] running: {cmdline}")
        t = threading.Thread(target=self.thread_fn, args=[id, cmdline, self.callback])
        t.start()

    def force_quit(self):
        """
        Terminates the running command forcefully.
        """
        self.process.kill()


class Curl(CmdWrapper):
    def __init__(self, exe=resource_path("bin/curl.exe"), callback=None, proxy=None):
        super().__init__(exe, callback)
        self.proxy = proxy
        self.t: threading.Thread = None

    ## todo: get http code from curl for error handling
    def query(self, url, headers={}, cookies={}):
        cmdline = [self.exe, url]

        if self.proxy is not None:
            cmdline.append("--proxy")
            cmdline.append(f"{self.proxy}")
            cmdline.append("--ssl-no-revoke")

        for header, value in headers.items():
            cmdline.append("-H")
            cmdline.append(f"{header}: {value}")

        print(f"[+] calling curl with: {cmdline}")
        t = threading.Thread(target=self.thread_fn, args=[cmdline, self.callback])
        t.daemon = True
        t.start()


class LibCurl:
    """
    A class that provides methods for performing HTTP requests using libcurl.

    Args:
        callback (function, optional): The callback function to be called after the request is completed. Defaults to None.
        internetConfig (tuple, optional): A tuple containing the tunnel URL, proxy, and authentication information. Defaults to ().
        debug (bool, optional): A flag indicating whether to enable debug mode. Defaults to False.
    """

    def __init__(self, callback=None, internetConfig=(), debug=False):
        self.callback = callback
        (self.tunnelUrl, self.proxy, self.auth) = internetConfig
        self.debug = debug

    def thread_fn(self, id, originalText, url, callback, headers=None, cookies=None):
        """
        Perform an HTTP request using libcurl in a separate thread.

        Args:
            id (int): The ID of the request.
            originalText (str): The original text associated with the request.
            url (str): The URL to send the request to.
            callback (function): The callback function to be called after the request is completed.
            headers (list, optional): Additional headers to include in the request. Defaults to None.
            cookies (list, optional): Cookies to include in the request. Defaults to None.

        Returns:
            None
        """
        handle = pycurl.Curl()
        if self.debug:
            handle.setopt(handle.VERBOSE, True)

        handle.setopt(
            pycurl.USERAGENT,
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
        )

        buffer = io.BytesIO()
        handle.setopt(pycurl.WRITEFUNCTION, buffer.write)
        handle.setopt(pycurl.URL, url)

        if self.proxy is not None:
            handle.setopt(pycurl.PROXY, self.proxy)
            handle.setopt(
                pycurl.PROXYHEADER, [f"Proxy-Authorization: Basic {self.auth}"]
            )
            handle.setopt(pycurl.SSL_OPTIONS, handle.SSLOPT_NO_REVOKE)

        if headers is not None:
            handle.setopt(pycurl.HTTPHEADER, headers)
        try:
            handle.perform()
        except Exception as e:
            print(f"[libcurl] network error: {e}")
        code: int = handle.getinfo(pycurl.RESPONSE_CODE)
        body = buffer.getvalue()

        handle.close()
        buffer.close()
        callback(id, (code, originalText, body.decode()))

    def tunnel_thread_fn(
        self,
        id,
        originalText,
        tunnelUrl,
        callback,
        headers=None,
        cookies=None,
        data=None,
    ):
        """
        Perform a tunnel request using libcurl in a separate thread.

        Args:
            id (int): The ID of the tunnel request.
            originalText (str): The original text associated with the tunnel request.
            tunnelUrl (str): The URL to send the tunnel request to.
            callback (function): The callback function to be called after the tunnel request is completed.
            headers (list, optional): Additional headers to include in the tunnel request. Defaults to None.
            cookies (list, optional): Cookies to include in the tunnel request. Defaults to None.
            data (dict, optional): The data to send in the tunnel request body. Defaults to None.

        Returns:
            None
        """
        c = pycurl.Curl()
        c.setopt(c.URL, tunnelUrl)
        buffer = io.BytesIO()
        c.setopt(pycurl.WRITEFUNCTION, buffer.write)
        c.setopt(
            pycurl.USERAGENT,
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
        )
        headers = ["Accept:application/json", "Content-Type:application/json"]

        c.setopt(pycurl.HTTPHEADER, headers)
        if data is not None:
            datas = json.dumps(data)
            c.setopt(c.POSTFIELDS, datas)
        try:
            c.perform()
        except Exception as e:
            print(f"[libcurl] network error: {e}")
        code: int = c.getinfo(pycurl.RESPONSE_CODE)
        body = buffer.getvalue()

        c.close()
        buffer.close()
        callback(id, (code, originalText, body.decode()))

    def query(self, id, originalText, url, headers={}, cookies={}):
        """
        Perform an HTTP request using libcurl in a separate thread.

        Args:
            id (int): The ID of the request.
            originalText (str): The original text associated with the request.
            url (str): The URL to send the request to.
            headers (dict, optional): Additional headers to include in the request. Defaults to {}.
            cookies (dict, optional): Cookies to include in the request. Defaults to {}.

        Returns:
            None
        """
        pc_headers = []
        for header, value in headers.items():
            pc_headers.append(f"{header}: {value}")

        t = threading.Thread(
            target=self.thread_fn,
            args=[id, originalText, url, self.callback, pc_headers, cookies],
        )
        t.daemon = True
        t.start()

    def tunnel(self, id, originalText, tunnelUrl, data):
        """
        Perform a tunnel request using libcurl in a separate thread.

        Args:
            id (int): The ID of the tunnel request.
            originalText (str): The original text associated with the tunnel request.
            tunnelUrl (str): The URL to send the tunnel request to.
            data (dict): The data to send in the tunnel request body.

        Returns:
            None
        """
        headers = ["Accept:application/json"]

        t = threading.Thread(
            target=self.tunnel_thread_fn,
            args=[id, originalText, tunnelUrl, self.callback, headers, None, data],
        )
        t.daemon = True
        t.start()


class NetUser(CmdWrapper):
    """
    Represents a network user.

    This class provides methods to query information about a network user using the 'net.exe' command.

    Args:
        ui: The user interface object.

    Attributes:
        ui: The user interface object.
    """

    def __init__(self, ui):
        super().__init__("net.exe")
        self.ui = ui

    def parse(self, text):
        """
        Parses the response text and returns the parsed result.

        Args:
            text: The response text to parse.

        Returns:
            The parsed result.
        """
        return text

    def query(self, id, user, domain=True):
        """
        Queries information about a network user.

        Args:
            id: The ID of the query.
            user: The username of the network user.
            domain: Whether to query the user in the domain (default is True).

        """

        def callback(id, response):
            result = self.parse(response)
            self.ui.render(source="netuser", box=(id, user, result))

        cmdline = [self.exe, "user"]
        if domain:
            cmdline.append("/domain")

        cmdline.append(user)
        print(f"[worker] calling: {cmdline}")
        t = threading.Thread(target=self.thread_fn, args=[id, cmdline, callback])
        t.daemon = True
        t.start()


class Base64Decoder:
    """
    A class that decodes Base64 encoded strings.

    Args:
        ui: The user interface object.

    Attributes:
        ui: The user interface object.

    Methods:
        query: Decodes a Base64 encoded string and renders the result in the user interface.

    """

    def __init__(self, ui):
        self.ui = ui

    def query(self, id, s):
        """
        Decodes a Base64 encoded string and renders the result in the user interface.

        Args:
            id: The identifier for the query.
            s: The Base64 encoded string to decode.

        Returns:
            None

        """
        import base64

        try:
            result = base64.b64decode(s, validate=True)
            decodedText = result.decode("utf-8")  # will add detection later
        except Exception as e:
            print(f"[base64decoder] encounter error: {e}")
            decodedText = None
        self.ui.render(source="base64", box=(id, s, decodedText))


class AbuseIPDB:
    """
    Class representing the AbuseIPDB API.

    Attributes:
        apiKey (str): The API key for accessing the AbuseIPDB API.
        ui (UI): A reference to the UI object.
        internetConfig (InternetConfig): The internet configuration.
        curlDebug (bool): Flag indicating whether to enable debug mode for LibCurl.
        curl (LibCurl): The LibCurl object for making HTTP requests.
        running (bool): Flag indicating whether the AbuseIPDB is running.
    """

    def __init__(self, apiKey, ui):
        """
        Initializes an instance of the AbuseIPDB class.

        Args:
            apiKey (str): The API key for accessing the AbuseIPDB API.
            ui (UI): A reference to the UI object.
        """

        def callback(id, response):
            (code, originalText, body) = response
            # parse response, since result is json
            if code == 200 and body != "":
                try:
                    jsonData = json.loads(body)
                    abuseObject = AbuseObject(**jsonData)
                except Exception as e:
                    print(f"[worker-abuseipdb] error: {e}")
                    abuseObject = None
                ui.render(source="abuseipdb", box=(id, originalText, abuseObject))

        if apiKey is None:
            print("[abuseipdb] api key not provided, abuseipdb might not work")
            self.apiKey = ""
        else:
            self.apiKey = apiKey

        self.ui = ui  # a ref to UI object
        self.internetConfig = self.ui.config.get_internet_config()
        self.curlDebug = self.ui.config.get_network_debug()
        self.curl = LibCurl(
            callback=callback, internetConfig=self.internetConfig, debug=self.curlDebug
        )
        self.running = False

    def timeout(self, id, text, sec):
        """
        Sets a timeout for rendering the AbuseIPDB response.

        Args:
            id (int): The ID of the request.
            text (str): The IP address being queried.
            sec (int): The timeout duration in seconds.
        """
        self.ui.after(
            sec,
            lambda: self.ui.render(source="abuseipdb", box=(id, text, None)),
        )

    @cache
    def query(self, id, text, maxAge=90):
        """
        Queries the AbuseIPDB API for information about an IP address.

        Args:
            id (int): The ID of the request.
            text (str): The IP address to query.
            maxAge (int): The maximum age of the data in days (default: 90).
        """
        headers = {
            "Key": self.apiKey,
            "Accept": "application/json",
        }
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={text}&verbose&maxAgeInDays={maxAge}"
        try:
            if self.internetConfig[0] is not None:
                self.timeout(id, text, 4000)
                tunnelUrl = self.internetConfig[0]
                pc_headers = []
                for header, value in headers.items():
                    pc_headers.append(f"{header}: {value}")
                data = {
                    "service": TunnelService.ABUSEIPDB,
                    "url": url,
                    "headers": pc_headers,
                }
                self.curl.tunnel(id, text, tunnelUrl, data)
            else:
                self.timeout(id, text, 8000)
                self.curl.query(id, text, url, headers)
        except Exception as e:
            print(f"[worker-abuseipdb] error: {e}")
            self.ui.render(source="abuseipdb", box=(id, text, None))


class Shodan:
    def __init__(self, apiKey, ui):
        def callback(id, response):
            (code, originalText, body) = response
            print(body)
            if code == 200 and body != "":
                try:
                    jsonData = json.loads(body)
                    shodanObject = ShodanObject(**jsonData)
                except Exception as e:
                    print(f"[worker-shodan] error: {e}")
                    shodanObject = None
                ui.render(source="shodan", box=(id, originalText, shodanObject))

        if apiKey is None:
            print("[shodan] api key not provived, shodan will not work")
            self.apiKey = ""

        self.apiKey = apiKey
        self.ui = ui
        self.internetConfig = self.ui.config.get_internet_config()
        self.curlDebug = self.ui.config.get_network_debug()
        self.curl = LibCurl(
            callback=callback, internetConfig=self.internetConfig, debug=self.curlDebug
        )

    def timeout(self, id, text, sec):
        self.ui.after(
            sec,
            lambda: self.ui.render(source="shodan", box=(id, text, None)),
        )

    @cache
    def query(self, id, text):
        url = f"https://api.shodan.io/shodan/host/{text}?key={self.apiKey}&minify=false"
        try:
            if self.internetConfig[0] is not None:
                self.timeout(id, text, 4000)
                tunnelUrl = self.internetConfig[0]
                data = {"service": TunnelService.SHODAN, "url": url}
                self.curl.tunnel(id, text, tunnelUrl, data)
            else:
                self.timeout(id, text, 8000)
                self.curl.query(id, text, url)
        except Exception as e:
            print(f"[worker-shodan] error: {e}")
            self.ui.render(source="shodan", box=(id, text, None))


class LocalIPWizard:
    """
    A class that provides functionality for resolving IP addresses and retrieving IP information.

    Args:
        ui: The user interface object.

    Attributes:
        ui: The user interface object.
        tunnel: The tunnel string.
        ipInfo: An instance of LocalIpInfo class for querying IP information.

    Methods:
        thread_fn: A helper method for performing IP address resolution in a separate thread.
        query: Resolves an IP address and retrieves IP information.

    """

    def __init__(self, ui):
        self.ui = ui
        ipdb = ui.config.get_local_ip_db()
        self.tunnel = ui.config.get_tunnel_string()
        self.ipInfo = LocalIpInfo(dataFile=ipdb, tunnel=self.tunnel)

    def thread_fn(self, id, host, callback, reverse):
        """
        A helper method for performing IP address resolution in a separate thread.

        Args:
            id: The ID of the query.
            host: The host to resolve.
            callback: The callback function to be called with the result.
            reverse: A boolean indicating whether to perform reverse DNS lookup.

        """
        ipInfo = ""
        resp = ""
        try:
            if reverse:
                ipInfo = self.ipInfo.query(host)
                self.ui.after(500, lambda: callback(id, (resp, ipInfo)))
                resp = socket.gethostbyaddr(host)[0]
            else:
                self.ui.after(800, lambda: callback(id, (resp, ipInfo)))
                resp = socket.gethostbyname(host)
                ipInfo = self.ipInfo.query(resp)
        except Exception as e:
            print(f"[wizard] error: {e}")
        callback(id, (resp, ipInfo))

    @cache
    def query(self, id, host, reverse=False):
        """
        Resolves an IP address and retrieves IP information.

        Args:
            id: The ID of the query.
            host: The host to resolve.
            reverse: A boolean indicating whether to perform reverse DNS lookup.

        """

        def thread_callback(id, response):
            if response == ("", ""):
                result = f"{host} was not resolvable."
            else:
                (resp, ipInfo) = response
                result = f"{host} resolved to {resp if resp != '' else 'None'}\n---\n{ipInfo}"
            self.ui.render(source="dns", box=(id, host, result))

        t = threading.Thread(
            target=self.thread_fn, args=[id, host, thread_callback, reverse]
        )
        t.daemon = True
        t.start()


class VirusTotal:
    """
    Represents a VirusTotal object used for querying the VirusTotal API.

    Args:
        apiKey (str): The API key for accessing the VirusTotal API.
        ui (UI): A reference to the UI object.

    Attributes:
        apiKey (str): The API key for accessing the VirusTotal API.
        ui (UI): A reference to the UI object.
        internetConfig (InternetConfig): The internet configuration.
        curlDebug (bool): Flag indicating whether to enable network debugging.
        curl (LibCurl): The LibCurl object for making HTTP requests.

    """

    def __init__(self, apiKey, ui):
        def callback(id, response):
            (code, originalText, body) = response
            # parse response, since result is json
            if code == 200 and body != "":
                try:
                    jsonData = json.loads(body)
                    virusTotalObject = VirusTotalObject(**jsonData)
                except Exception as e:
                    print(f"[worker-virustotal] error: {e}")
                    virusTotalObject = None
                ui.render(source="virustotal", box=(id, originalText, virusTotalObject))

        if apiKey is None:
            print("[virustotal] api key not provided, virustotal might not work")
            self.apiKey = ""
        else:
            self.apiKey = apiKey

        self.ui = ui  # a ref to UI object
        self.internetConfig = self.ui.config.get_internet_config()
        self.curlDebug = self.ui.config.get_network_debug()
        self.curl = LibCurl(
            callback=callback, internetConfig=self.internetConfig, debug=self.curlDebug
        )

    def timeout(self, id, hash, sec):
        self.ui.after(
            sec,
            lambda: self.ui.render(source="virustotal", box=(id, hash, None)),
        )

    @cache
    def query(self, id, hash, options={}):
        headers = {
            "x-apikey": f"{self.apiKey}",
            "Accept": "application/json",
        }
        url = f"https://www.virustotal.com/api/v3/search?query={hash}"
        try:
            if self.internetConfig[0] is not None:
                self.timeout(id, hash, 5000)
                tunnelUrl = self.internetConfig[0]
                pc_headers = []
                for header, value in headers.items():
                    pc_headers.append(f"{header}: {value}")
                data = {
                    "service": TunnelService.VIRUSTOTAL,
                    "url": url,
                    "headers": pc_headers,
                }
                self.curl.tunnel(id, hash, tunnelUrl, data)
            else:
                self.timeout(id, hash, 10000)
                self.curl.query(id, hash, url, headers)
        except Exception as e:
            print(f"[worker-virustotal] error: {e}")
            self.ui.render(source="virustotal", box=(id, hash, None))


class NISTCVE:
    def __init__(self, ui):
        def callback(id, response):
            (code, originalText, body) = response
            # parse response, since result is json
            if code == 200 and body != "":
                try:
                    jsonData = json.loads(body)
                    nistObject = NISTObject(**jsonData)
                except Exception as e:
                    print(f"[worker-nist] error: {e}")
                    nistObject = None
                ui.render(source="cve", box=(id, originalText, nistObject))

        self.ui = ui  # a ref to UI object
        self.internetConfig = self.ui.config.get_internet_config()
        self.curlDebug = self.ui.config.get_network_debug()
        self.curl = LibCurl(
            callback=callback, internetConfig=self.internetConfig, debug=self.curlDebug
        )

    def timeout(self, id, cve, sec):
        self.ui.after(
            sec,
            lambda: self.ui.render(source="cve", box=(id, cve, None)),
        )

    @cache
    def query(self, id, cve, options={}):
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve.upper()}"
        try:
            if self.internetConfig[0] is not None:
                self.timeout(id, cve, 5000)
                tunnelUrl = self.internetConfig[0]
                data = {"url": url}
                self.curl.tunnel(id, cve, tunnelUrl, data)
            else:
                self.timeout(id, cve, 10000)
                self.curl.query(id, cve, url)
        except Exception as e:
            print(f"[worker-nist] error: {e}")
            self.ui.render(source="cve", box=(id, cve, None))


class CirclCVE:
    """
    A class that represents a CirclCVE object.

    Attributes:
        ui (UI): A reference to the UI object.
        internetConfig (dict): The internet configuration.
        curlDebug (bool): Flag indicating whether to enable curl debugging.
        curl (LibCurl): An instance of the LibCurl class.

    Methods:
        timeout(id, cve, sec): Sets a timeout for rendering the CirclCVE object.
        query(id, cve, options={}): Queries the CirclCVE API for a specific CVE.
    """

    def __init__(self, ui):
        def callback(id, response):
            (code, originalText, body) = response
            # parse response, since result is json
            if code == 200 and body != "":
                try:
                    if body == "null":
                        jsonData = {}
                    else:
                        jsonData = json.loads(body)
                    circlObject = CirclCVEObject(**jsonData)
                except Exception as e:
                    print(f"[worker-circl] error: {e}")
                    circlObject = None
                ui.render(source="circlcve", box=(id, originalText, circlObject))

        self.ui = ui  # a ref to UI object
        self.internetConfig = self.ui.config.get_internet_config()
        self.curlDebug = self.ui.config.get_network_debug()
        self.curl = LibCurl(
            callback=callback, internetConfig=self.internetConfig, debug=self.curlDebug
        )

    def timeout(self, id, cve, sec):
        """
        Sets a timeout for rendering the CirclCVE object.

        Args:
            id (int): The ID of the object.
            cve (str): The CVE identifier.
            sec (int): The number of seconds to wait before rendering.

        Returns:
            None
        """
        self.ui.after(
            sec,
            lambda: self.ui.render(source="circlcve", box=(id, cve, None)),
        )

    @cache
    def query(self, id, cve, options={}):
        """
        Queries the CirclCVE API for a specific CVE.

        Args:
            id (int): The ID of the object.
            cve (str): The CVE identifier.
            options (dict): Additional options for the query.

        Returns:
            None
        """
        url = f"https://cve.circl.lu/api/cve/{cve.upper()}"
        try:
            if self.internetConfig[0] is not None:
                self.timeout(id, cve, 5000)
                tunnelUrl = self.internetConfig[0]
                data = {"service": TunnelService.CIRCLCVE, "url": url}
                self.curl.tunnel(id, cve, tunnelUrl, data)
            else:
                self.timeout(id, cve, 10000)
                self.curl.query(id, cve, url)
        except Exception as e:
            print(f"[worker-circl] error: {e}")
            self.ui.render(source="cve", box=(id, cve, None))


class MacAddress:
    def __init__(self, ui):
        self.ui = ui
        self.handle = ouilookup.OuiLookup(
            data_file=resource_path("data/ouilookup.json")
        )

    def thread_fn(self, id, mac, callback):
        try:
            res = self.handle.query(mac)[0]
        except Exception:
            res = {f"{mac}": "Unknown"}
        callback(id, res)

    def query(self, id, mac):
        def thread_callback(id, response):
            vendor = "Unknown"
            for k, v in response.items():
                vendor = v
            message = f"Mac address {mac} indicates a network device from {vendor}"
            self.ui.render(source="mac", box=(id, mac, message))

        t = threading.Thread(target=self.thread_fn, args=[id, mac, thread_callback])
        t.daemon = True
        t.start()


class LocalIpInfo:
    def __init__(self, dataFile, tunnel=None):
        self.db = None
        self.dataFile = dataFile
        self.tunnel = tunnel
        self.disabled = False

    def remote_query(self, ip4, ip6=None):
        """
        offload the work to tunnel for more control over database
        """
        handle = pycurl.Curl()
        handle.setopt(handle.URL, self.tunnel)
        buffer = io.BytesIO()
        handle.setopt(pycurl.WRITEFUNCTION, buffer.write)
        handle.setopt(
            pycurl.USERAGENT,
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
        )
        headers = ["Accept:application/json", "Content-Type:application/json"]

        handle.setopt(pycurl.HTTPHEADER, headers)
        datas = json.dumps({"service": TunnelService.LOCALIP, "ip": ip4})
        handle.setopt(handle.POSTFIELDS, datas)
        try:
            handle.perform()
        except Exception as e:
            print(f"[libcurl] network error: {e}")
        code: int = handle.getinfo(pycurl.RESPONSE_CODE)
        body = buffer.getvalue()
        handle.close()
        buffer.close()

        if code == 200:
            return body.decode()
        else:
            return f"Local IP {ip4} not found in database!"

    def query(self, ip):
        if self.tunnel is not None:
            return self.remote_query(ip)
        if self.db is None:
            try:
                file = open(self.dataFile, "rt")
                reader = csv.reader(file, delimiter=",")
                # schema cidr,usage,location,comment
                self.db = list(reader)
                file.close()
            except Exception as e:
                print(f"[localipinfo] error: {e}")
                self.disabled = True
        res = f"Local IP {ip} not found in database!"

        for row in self.db:
            try:
                if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(row[0]):
                    res = f"Local IP Address {ip} belongs to {row[0]}\nUsed for: {row[1]}\nLocated at: {row[2]}\nComment: {row[3]}"
            except Exception:
                continue

        return res


class TesserOCR:
    def __init__(self, ui):
        """
        Initiates PyTessBaseAPI lazily
        TODO: enhancing images before passing to tesseract
        """
        from tesserocr import PyTessBaseAPI
        import os

        self.ui = ui
        if os.path.isfile("data/eng.traineddata"):
            self.api = PyTessBaseAPI("data")
            self.disabled = False
        else:
            print(
                "[worker-ocr] error: OCR data file not found, this feature will not work"
            )
            self.disabled = True

    def thread_fn(self, id, img, callback):
        try:
            self.api.SetImage(img)
            res = self.api.GetUTF8Text()
        except Exception as e:
            print(f"[worker-ocr] error: {e}")
            res = ""
        callback(id, res)

    def query(self, id, img):
        if self.disabled:
            self.ui.render(
                source="ocr",
                box=(id, "image from clipboard", "<error: no ocr data found>"),
            )
            return

        def thread_callback(id, response):
            self.ui.render(
                source="ocr",
                box=(id, f'Image from clipboard "{response[:10]}"', response),
            )

        t = threading.Thread(target=self.thread_fn, args=[id, img, thread_callback])
        t.daemon = True
        t.start()


class DTSWorker:
    """
    DTSWorker class represents a worker that performs various tasks based on the given target.

    Args:
        config (object): The configuration object.
        ui (object): The user interface object.

    Attributes:
        isWorking (bool): Indicates whether the worker is currently working.
        config (object): The configuration object.
        ui (object): The user interface object.
        virusTotal (object): The VirusTotal API object.
        abuseIPDB (object): The AbuseIPDB API object.
        circleCVE (object): The CirclCVE object.
        netUser (object): The NetUser object.
        base64Decoder (object): The Base64Decoder object.
        localIPWizard (object): The LocalIPWizard object.
        macAddressLookup (object): The MacAddress object.
        ocrApi (object): The TesserOCR object.
    """

    def __init__(self, config, ui):
        self.isWorking = False
        self.config = config
        self.ui = ui

        virusTotalKey = self.config.get("api", "virustotal")
        abuseIPDBKey = self.config.get("api", "abuseipdb")

        self.virusTotal = VirusTotal(apiKey=virusTotalKey, ui=self.ui)
        self.abuseIPDB = AbuseIPDB(apiKey=abuseIPDBKey, ui=self.ui)
        self.circleCVE = CirclCVE(ui=self.ui)
        self.netUser = NetUser(ui=self.ui)
        self.base64Decoder = Base64Decoder(ui=self.ui)
        self.localIPWizard = LocalIPWizard(ui=self.ui)
        self.macAddressLookup = MacAddress(ui=self.ui)
        self.ocrApi = TesserOCR(ui=self.ui)

    def run(self, id, target={}, text="", img=None):
        """
        Runs the worker with the given target.

        Args:
            id (int): The ID of the task.
            target (dict): The target to be queried.
            text (str): The text to be queried.
            img (object): The image object to be queried.
        """
        print(f"[worker] trying to run {target} with target = `{text}`")
        for t in target:
            if t == "virustotal":
                self.virusTotal.query(id, text)
            elif t == "abuseipdb":
                self.abuseIPDB.query(id, text)
            elif t == "cve":
                self.circleCVE.query(id, text)
            elif t == "netuser":
                self.netUser.query(id, text)
            elif t == "base64":
                self.base64Decoder.query(id, text)
            elif t == "dns":
                self.localIPWizard.query(id, text)
            elif t == "rdns":
                self.localIPWizard.query(id, text, reverse=True)
            elif t == "mac":
                self.macAddressLookup.query(id, text)
            elif t == "ocr":
                self.ocrApi.query(id, img)
            else:
                pass
