import io
import simdjson
import threading
import pycurl
from .util import resource_path
from .structure import AbuseObject, VirusTotalObject


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
    def __init__(self, callback=None, proxy=None):
        self.callback = callback
        self.proxy = proxy

    def thread_fn(self, id, url, callback, headers=None, cookies=None, debug=False):
        handle = pycurl.Curl()
        if debug:
            handle.setopt(handle.VERBOSE, True)
        buffer = io.BytesIO()

        handle.setopt(
            handle.USERAGENT,
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        )
        handle.setopt(handle.WRITEFUNCTION, buffer.write)
        handle.setopt(handle.URL, url)

        if self.proxy is not None:
            handle.setopt(handle.PROXY, self.proxy)
            handle.setopt(handle.SSL_OPTIONS, handle.SSLOPT_NO_REVOKE)

        if headers is not None:
            handle.setopt(handle.HTTPHEADER, headers)
        handle.perform()
        code: int = handle.getinfo(handle.RESPONSE_CODE)
        body = buffer.getvalue()

        handle.close()
        buffer.close()
        callback(id, (code, body.decode()))

    def query(self, id, url, headers={}, cookies={}):
        pc_headers = []
        for header, value in headers.items():
            pc_headers.append(f"{header}: {value}")

        t = threading.Thread(
            target=self.thread_fn, args=[id, url, self.callback, pc_headers, cookies]
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
            self.ui.render(source="netuser", box=(id, result))

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
        except Exception as e:
            print(f"[base64decoder] encounter error: {e}")
            return
        self.ui.render(source="base64", box=(id, result))


class AbuseIPDB:
    def __init__(self, apiKey, ui):
        def callback(id, response):
            (code, body) = response
            # parse response, since result is json
            if code == 200 and body != "":
                jsonData = simdjson.loads(body)
                abuseObject = AbuseObject(**jsonData)
                ui.render(source="abuseipdb", box=(id, abuseObject))

        self.apiKey = apiKey
        self.ui = ui  # a ref to UI object
        self.useProxy: None | str = self.ui.config.get_proxy_string()
        self.curl = LibCurl(callback=callback, proxy=self.useProxy)
        self.running = False

    def query(self, id, text, maxAge=90):
        headers = {
            "Key": self.apiKey,
            "Accept": "application/json",
        }
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={text}&maxAgeInDays={maxAge}"
        self.curl.query(id, url, headers)


class VirusTotal:
    def __init__(self, apiKey, ui):
        def callback(id, response):
            (code, body) = response
            # parse response, since result is json
            if code == 200 and body != "":
                jsonData = simdjson.loads(body)
                virusTotalObject = VirusTotalObject(**jsonData)
                ui.render(source="virustotal", box=(id, virusTotalObject))

        self.ui = ui  # a ref to UI object
        self.apiKey = apiKey
        self.useProxy: None | str = self.ui.config.get_proxy_string()
        self.curl = LibCurl(callback=callback, proxy=self.useProxy)

    def query(self, id, hash, options={}):
        headers = {"x-apikey": f"{self.apiKey}"}

        url = f"https://www.virustotal.com/api/v3/search?query={hash}"
        self.curl.query(id, url, headers)


class DTSWorker:
    def __init__(self, config, ui):
        self.isWorking = False
        self.config = config
        self.ui = ui
        try:
            virusTotalAPI = self.config.get("api", "virustotal")
        except Exception as e:
            raise e
        try:
            abuseIPDBAPI = self.config.get("api", "abuseipdb")
        except Exception as e:
            raise e

        self.virusTotal = VirusTotal(apiKey=virusTotalAPI, ui=self.ui)
        self.abuseIPDB = AbuseIPDB(apiKey=abuseIPDBAPI, ui=self.ui)
        self.netUser = NetUser(ui=self.ui)
        self.base64Decoder = Base64Decoder(ui=self.ui)

    def run(self, id, target={}, data=""):
        for t in target:
            if t == "virustotal":
                self.virusTotal.query(id, data)
                self.isWorking = True
            elif t == "abuseipdb":
                self.abuseIPDB.query(id, data)
                self.isWorking = True
            elif t == "netuser":
                self.netUser.query(id, data)
            elif t == "base64":
                self.base64Decoder.query(id, data)
            else:
                pass
