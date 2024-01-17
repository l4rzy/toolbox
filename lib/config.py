from pathlib import Path
print('Running' if __name__ == '__main__' else 'Importing', Path(__file__).resolve())

class Config:
    def __init__(self, configFile='config.ini'):
        import configparser
        self.configFile = configFile
        self.config = configparser.ConfigParser(allow_no_value=True)

        self.run()

    def generate_default(self):
        self.config.read_string("""
[api]
abuseipdb = abcdefa89737fasjsf8721389r23jnr328ry2ui3jrn
[ui]
scaling = 2.0
dx = 300
dy = 700
dropdown_items = 10
""")
        with open(self.configFile, 'wt+') as f:
            self.config.write(f)
    
    def get(self, section, configString):
        try:
            return self.config[section][configString]
        except Exception as e:
            print(e)
            return None
        
    def set(self, section, key, value):
        self.config[section][key] = value
        
    def get_dimension(self):
        return (self.get('ui', 'dx'), self.get('ui', 'dy'))
    
    def persist(self):
        with open(self.configFile, 'wt+') as f:
            self.config.write(f)

    def run(self):
        import  os
        
        if os.path.isfile(self.configFile):
            with open (self.configFile, 'rt') as f:
                self.config.read_file(f)
        else:
            self.generate_default()
