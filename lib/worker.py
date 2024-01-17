from pathlib import Path
print('Running' if __name__ == '__main__' else 'Importing', Path(__file__).resolve())

import json, threading

class AbuseIPDB:
    def __init__(self, apiKey):
        self.apiKey = apiKey

    def query(self, text, maxAge=90):
        import requests

        headers = {
            'Key': self.apiKey,
            'Accept': 'application/json',
        }

        response = requests.get(
            f'https://api.abuseipdb.com/api/v2/check?ipAddress={text}&maxAgeInDays={maxAge}&verbose',
            headers=headers,
        )

        data = json.loads(response.text)
        print(json.dumps(data, indent=2))

class AbuseIPDBT(threading.Thread):
    def __init__(self, id, data, flag):
        super().__init__()
        self.id = id
        self.stop_flag = flag

    def run(self):
        while not self.stop_flag:
            pass

