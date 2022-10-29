class AnalystProfile:
    def __init__(self, config):
        self.name = config['name']
        self.api_keys = config['api_keys']
        self.abuseipdb_api_key = self.api_keys['abuseipdb']
        self.virustotal_api_key = self.api_keys['virustotal']
        self.securitytrails_api_key = self.api_keys['securitytrails']
        self.shodan_api_key = self.api_keys['shodan']
        self.censys_api_key = self.api_keys['censys']['api_id']
        self.censys_secret = self.api_keys['censys']['secret']
        self.arguments = config['arguments']

    def print_config(self):
        print(f"name: {self.name}")
        print(f"abuseipdb: {self.abuseipdb_api_key}")
        print(f"virustotal: {self.virustotal_api_key}")
        print(f"securitytrails: {self.securitytrails_api_key}")
        print(f"shodan: {self.shodan_api_key}")
        print(f"censys_api_id: {self.censys_api_key}")
        print(f"censys_secret: {self.censys_secret}")
        print(f"arguments: {self.arguments}")
