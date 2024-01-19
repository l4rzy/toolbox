import time
import json, threading
import subprocess

from .util import resource_path

class CmdWrapper:
    def __init__(self, exe='', callback = None):
        self.exe = exe
        self.callback = callback
        self.process = None

    def thread_fn(self, cmdline, callback):
        self.process = subprocess.Popen(cmdline, stdout=subprocess.PIPE)
        while self.process.poll() == None:
            pass
            time.sleep(0.05)

        callback(self.process.stdout.read())
        self.process.terminate()

    def query(self, args):
        cmdline = [self.exe, args]

        print(f'[+] running {self.exe} with cmdline: {cmdline}')
        t = threading.Thread(target=self.thread_fn, args=[cmdline, self.callback])
        t.start()

    def force_quit(self):
        self.process.kill()

class Curl(CmdWrapper):
    def __init__(self, exe=resource_path('curl\\curl.exe'), callback = None):
        super().__init__(exe, callback)

    def query(self, url, headers = {}, cookies = {}):
        cmdline = [self.exe, url]

        for header, value in headers.items():
            cmdline.append('-H')
            cmdline.append(f'{header}: {value}')

        print(f'[+] running curl with cmdline: {cmdline}')
        t = threading.Thread(target=self.thread_fn, args=[cmdline, self.callback])
        t.start()

class NetUser(CmdWrapper):
    def __init__(self, exe='net.exe', callback = None):
        super().__init__(exe, callback)

class AbuseIPDB:
    def __init__(self, apiKey, ui):
        def callback(response):
            # parse response, since result is json
            if response:
                data = json.loads(response)
                ui.render('abuseipdb', data)
        self.apiKey = apiKey
        self.ui = ui # a ref to UI object
        self.curl = Curl(callback=callback)

    def query(self, text, maxAge=90):
        headers = {
            'Key': self.apiKey,
            'Accept': 'application/json',
        }
        url = f'https://api.abuseipdb.com/api/v2/check?ipAddress={text}&maxAgeInDays={maxAge}'
        self.curl.query(url, headers)

class VirusTotal:
    def __init__(self):
        pass
