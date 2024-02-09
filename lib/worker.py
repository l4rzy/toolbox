import io

try:
    import simdjson
except Exception:
    print("[worker] falling back to vanilla cpython json")
    import json as simdjson
import threading
import pycurl
from .util import resource_path
from .structure import AbuseObject, VirusTotalObject, ShodanObject, NISTObject
import ouilookup
import ipaddress
import csv
from functools import cache
import socket

class CmdWrapper:
    def __init__(self, exe=""):
        self.exe = exe
        self.process = None

    def thread_fn(self, id, cmdline, callback):
        import uuid
        import os
        import subprocess
        from pathlib import Path

        Path(".\\tmp").mkdir(exist_ok=True)
        # use temp file due to subprocess stdout = PIPE blocks itself
        ftempName = f"tmp\\{uuid.uuid4()}.bin"
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
        import subprocess

        self.process = subprocess.Popen(cmdline, stdout=subprocess.PIPE, stderr=None)
        # while self.process.poll() is None:
        #    time.sleep(0.05)
        self.process.wait(timeout=5)
        output, _ = self.process.communicate()
        callback(id, output)

    def query(self, id, args):
        cmdline = [self.exe, args]

        print(f"[worker] running: {cmdline}")
        t = threading.Thread(target=self.thread_fn, args=[id, cmdline, self.callback])
        t.start()

    def force_quit(self):
        self.process.kill()


class Curl(CmdWrapper):
    def __init__(self, exe=resource_path("bin\\curl.exe"), callback=None, proxy=None):
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
    def __init__(self, callback=None, proxyConfig=(), debug=False):
        self.callback = callback
        (self.proxy, self.auth) = proxyConfig
        self.debug = debug

    def thread_fn(self, id, originalText, url, callback, headers=None, cookies=None):
        handle = pycurl.Curl()
        if self.debug:
            handle.setopt(handle.VERBOSE, True)
        buffer = io.BytesIO()

        handle.setopt(
            handle.USERAGENT,
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
        )
        handle.setopt(handle.WRITEFUNCTION, buffer.write)
        handle.setopt(handle.URL, url)

        if self.proxy is not None:
            handle.setopt(handle.PROXY, self.proxy)
            handle.setopt(
                pycurl.PROXYHEADER, [f"Proxy-Authorization: Basic {self.auth}"]
            )
            handle.setopt(handle.SSL_OPTIONS, handle.SSLOPT_NO_REVOKE)

        if headers is not None:
            handle.setopt(handle.HTTPHEADER, headers)
        handle.perform()
        code: int = handle.getinfo(handle.RESPONSE_CODE)
        body = buffer.getvalue()

        handle.close()
        buffer.close()
        callback(id, (code, originalText, body.decode()))

    def query(self, id, originalText, url, headers={}, cookies={}):
        pc_headers = []
        for header, value in headers.items():
            pc_headers.append(f"{header}: {value}")

        t = threading.Thread(
            target=self.thread_fn,
            args=[id, originalText, url, self.callback, pc_headers, cookies],
        )
        t.daemon = True
        t.start()


class NetUser(CmdWrapper):
    def __init__(self, ui):
        super().__init__("net.exe")
        self.ui = ui

    def parse(self, text):
        return text

    def query(self, id, user, domain=True):
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
    def __init__(self, ui):
        self.ui = ui

    def query(self, id, s):
        import base64

        try:
            result = base64.b64decode(s.encode("utf-8"))
            decodedText = result.decode("utf-8")  # will add detection later
        except Exception as e:
            print(f"[base64decoder] encounter error: {e}")
            decodedText = None
        self.ui.render(source="base64", box=(id, s, decodedText))


class AbuseIPDB:
    def __init__(self, apiKey, ui):
        def callback(id, response):
            (code, originalText, body) = response
            # parse response, since result is json
            if code == 200 and body != "":
                jsonData = simdjson.loads(body)
                abuseObject = AbuseObject(**jsonData)
                ui.render(source="abuseipdb", box=(id, originalText, abuseObject))

        if apiKey is None:
            print("[abuseipdb] api key not provived, abuseipdb will not work")
            self.apiKey = ""

        self.apiKey = apiKey
        self.ui = ui  # a ref to UI object
        self.proxyConfig = self.ui.config.get_proxy_config()
        self.curlDebug = self.ui.config.get_network_debug()
        self.curl = LibCurl(
            callback=callback, proxyConfig=self.proxyConfig, debug=self.curlDebug
        )
        self.running = False

    @cache
    def query(self, id, text, maxAge=90):
        headers = {
            "Key": self.apiKey,
            "Accept": "application/json",
        }
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={text}&maxAgeInDays={maxAge}"
        self.curl.query(id, text, url, headers)


class Shodan:
    def __init__(self, apiKey, ui):
        def callback(id, response):
            (code, originalText, body) = response
            print(body)
            if code == 200 and body != "":
                jsonData = simdjson.loads(body)
                shodanObject = ShodanObject(**jsonData)
                ui.render(source="shodan", box=(id, originalText, shodanObject))

        if apiKey is None:
            print("[shodan] api key not provived, shodan will not work")
            self.apiKey = ""

        self.apiKey = apiKey
        self.ui = ui
        self.proxyConfig = self.ui.config.get_proxy_config()
        self.curlDebug = self.ui.config.get_network_debug()
        self.curl = LibCurl(
            callback=callback, proxyConfig=self.proxyConfig, debug=self.curlDebug
        )

    def query(self, id, text):
        url = f"https://api.shodan.io/shodan/host/{text}?key={self.apiKey}&minify=false"
        self.curl.query(id, text, url)


class LocalIPWizard:
    def __init__(self, ui):
        self.ui = ui
        ipdb = ui.config.get_local_ip_db()
        self.ipInfo = LocalIpInfo(dataFile=ipdb)

    def thread_fn(self, id, host, callback, reverse):
        ipInfo = ""
        resp = ""
        try:
            if reverse:
                ipInfo = self.ipInfo.query(host)
                resp = socket.gethostbyaddr(host)
            else:
                resp = socket.gethostbyname(host)
                ipInfo = self.ipInfo.query(resp)
        except Exception as e:
            print(f'[wizard] error: {e}')
        callback(id, (resp, ipInfo))

    @cache
    def query(self, id, host, reverse=False):
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
    def __init__(self, apiKey, ui):
        def callback(id, response):
            (code, originalText, body) = response
            # parse response, since result is json
            if code == 200 and body != "":
                jsonData = simdjson.loads(body)
                virusTotalObject = VirusTotalObject(**jsonData)
                ui.render(source="virustotal", box=(id, originalText, virusTotalObject))

        if apiKey is None:
            print("[virustotal] api key not provived, virustotal will not work")
            self.apiKey = ""

        self.ui = ui  # a ref to UI object
        self.apiKey = apiKey
        self.proxyConfig = self.ui.config.get_proxy_config()
        self.curlDebug = self.ui.config.get_network_debug()
        self.curl = LibCurl(
            callback=callback, proxyConfig=self.proxyConfig, debug=self.curlDebug
        )

    @cache
    def query(self, id, hash, options={}):
        headers = {"x-apikey": f"{self.apiKey}"}

        url = f"https://www.virustotal.com/api/v3/search?query={hash}"
        self.curl.query(id, hash, url, headers)


class NISTCVE:
    def __init__(self, ui):
        def callback(id, response):
            (code, originalText, body) = response
            # parse response, since result is json
            if code == 200 and body != "":
                jsonData = simdjson.loads(body)
                nistObject = NISTObject(**jsonData)
                ui.render(source="cve", box=(id, originalText, nistObject))

        self.ui = ui  # a ref to UI object
        self.proxyConfig = self.ui.config.get_proxy_config()
        self.curlDebug = self.ui.config.get_network_debug()
        self.curl = LibCurl(
            callback=callback, proxyConfig=self.proxyConfig, debug=self.curlDebug
        )

    @cache
    def query(self, id, cve, options={}):
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve.upper()}"
        self.curl.query(id, cve, url)


class MacAddress:
    def __init__(self, ui):
        self.ui = ui
        self.handle = ouilookup.OuiLookup(data_file=resource_path("data\\ouilookup.json"))

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
    def __init__(self, dataFile):
        self.db = None
        self.dataFile = dataFile

    def query(self, ip):
        if self.db is None:
            file = open(self.dataFile, "rt")
            reader = csv.reader(file, delimiter=",")
            # schema cidr,usage,location,comment
            self.db = list(reader)
            file.close()
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
        from tesserocr import PyTessBaseAPI

        self.ui = ui
        self.api = PyTessBaseAPI("data")

    def thread_fn(self, id, img, callback):
        try:
            self.api.SetImage(img)
            res = self.api.GetUTF8Text()
        except Exception:
            res = ""
        callback(id, res)

    def query(self, id, img):
        def thread_callback(id, response):
            self.ui.render(
                source="ocr",
                box=(id, f'Image from clipboard "{response[:10]}"', response),
            )

        t = threading.Thread(target=self.thread_fn, args=[id, img, thread_callback])
        t.daemon = True
        t.start()


class DTSWorker:
    def __init__(self, config, ui):
        self.isWorking = False
        self.config = config
        self.ui = ui

        virusTotalKey = self.config.get("api", "virustotal")
        abuseIPDBKey = self.config.get("api", "abuseipdb")
        # shodanAPIKey = self.config.get("api", "shodan")

        self.virusTotal = VirusTotal(apiKey=virusTotalKey, ui=self.ui)
        self.abuseIPDB = AbuseIPDB(apiKey=abuseIPDBKey, ui=self.ui)
        self.nistCVE = NISTCVE(ui=self.ui)
        self.netUser = NetUser(ui=self.ui)
        self.base64Decoder = Base64Decoder(ui=self.ui)
        # self.shodan = Shodan(apiKey=shodanAPIKey, ui=self.ui)
        self.localIPWizard = LocalIPWizard(ui=self.ui)
        self.macAddressLookup = MacAddress(ui=self.ui)
        self.ocrApi = TesserOCR(ui=self.ui)

    def run(self, id, target={}, text="", img=None):
        print(f"[worker] trying to run {target} with target = `{text}`")
        for t in target:
            if t == "virustotal":
                self.virusTotal.query(id, text)
            elif t == "abuseipdb":
                self.abuseIPDB.query(id, text)
            elif t == "cve":
                self.nistCVE.query(id, text)
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
