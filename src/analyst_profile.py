class AnalystProfile:
    def __init__(self, config):
        self.name = config['name']
        self.api_keys = config['api_keys']
        self.abuseipdb_api_key = self.api_keys['abuseipdb']
        self.virustotal_api_key = self.api_keys['virustotal']
        self.arguments = config['arguments']

    def test(self):
        print(self.name)
        print(self.abuseipdb_api_key)
        print(self.virustotal_api_key)
        print(self.arguments)