import re

# stolen from https://ihateregex.io/expr/ip/
IPV4ADDR = r'(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}'
IPV6ADDR = r'(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))'
GOMC = r'^GOMC\-([0-9])'

class Analyzer:
    def __init__(self, config = None):
        self.config = config
        self.text = ''
        self.insertable = False
        self.categorizers = {}
        self.categorizers['ipv4'] = re.compile(IPV4ADDR)
        self.categorizers['ipv6'] = re.compile(IPV6ADDR)
        self.dataClass = []

    def reset(self):
        self.text = ''
        self.insertable = False
        self.dataClass = []

    def process(self, text):
        print(f"analyzing `{text}`")
        self.text = text
        for type in self.categorizers:
            if self.categorizers[type].match(text):
                print(f'matched with {type}')
                self.dataClass.append(type)
                self.insertable = True
                break

    def is_ip(self):
        return any(item in self.dataClass for item in ['ipv4', 'ipv6'])