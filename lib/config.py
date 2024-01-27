import configparser

class DTSConfig:
    def __init__(self, configFile="config.ini"):

        self.defaultCfg = """
[general]
proxy = insert_your_proxy_string_here
ocr = true
[api]
abuseipdb = insert_your_abuseipdb_api_key_here
virustotal = insert_your_vt_api_key_here
shodan = insert_your_shodan_api_key_here # currently not in use
[ui]
analyze_on_focus = 1
iconify_on_escape = true
clipboard_max_length = 1000
dimension = 640x1022+10+10
"""
        self.configFile = configFile
        self.config = configparser.ConfigParser(allow_no_value=True)

        self.run()

    def generate_default(self):
        self.config.read_string(self.defaultCfg)
        with open(self.configFile, "wt+") as f:
            self.config.write(f)

    def use_default(self):
        self.config.read_string(self.defaultCfg)

    def get(self, section, configString):
        try:
            return self.config[section][configString]
        except Exception:
            print(
                f"[config] can not retrieve key `{configString}` in section `{section}`"
            )
            return None

    def set(self, section, key, value):
        self.config[section][key] = value

    def get_proxy_string(self) -> None | str:
        val = self.get("general", "proxy")
        if val == 'false':
            return None
        return val
    
    def get_proxy_config(self):
        val = self.get("general", "proxy_auth")
        return (self.get_proxy_string(), val)

    def get_iconify_on_escape(self):
        val = self.get("ui", "iconify_on_escape")
        if val is None or val == "false":
            return False
        else:
            return True

    def get_clipboard_max_length(self):
        val = self.get("ui", "clipboard_max_length")
        if val is None:
            print("[config] using default value of 1000")
            return 1000
        return int(val)

    def get_dimension(self):
        val = self.get("ui", "dimension")
        if val is None:
            return "640x1022+1893+323"
        else:
            return val

    def get_analyze_on_focus(self) -> bool:
        val = self.get("ui", "analyze_on_focus")
        if val is None or val == "false":
            return False
        else:
            return True

    def persist(self):
        with open(self.configFile, "wt+") as f:
            self.config.write(f)

    def run(self):
        import os

        if os.path.isfile(self.configFile):
            try:
                with open(self.configFile, "rt") as f:
                    self.config.read_file(f)
            except Exception as e:
                print(f"[config] can not read config due to {e}")
                print("[config] using default config")
                self.use_default()
