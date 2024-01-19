class Config:
    def __init__(self, configFile='config.ini'):
        import configparser
        self.configFile = configFile
        self.config = configparser.ConfigParser(allow_no_value=True)

        self.run()

    def generate_default(self):
        defaultCfg = '''
[general]
proxy_auth = something
[api]
abuseipdb = abcdefa89737fasjsf8721389r23jnr328ry2ui3jrn
[ui]
dropdown_items = 10
analyze_on_focus = 1
dimension = 640x1022+1893+323
'''                 
        self.config.read_string(defaultCfg)
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
    
    def get_analyze_on_focus(self):
        val = self.get('general', 'analyze_on_focus')
        return val != '0' and val != None

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
