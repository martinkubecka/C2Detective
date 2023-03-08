class AnalystProfile:
    def __init__(self, config):
        self.name = config['name']

        self.api_keys = config['api_keys']
        self.abuseipdb_api_key = self.api_keys['abuseipdb']
        self.virustotal_api_key = self.api_keys['virustotal']
        self.securitytrails_api_key = self.api_keys['securitytrails']
        self.shodan_api_key = self.api_keys['shodan']

        self.enrichment_services = config['enrichment_services']
        self.abuseipdb = self.enrichment_services['abuseipdb']
        self.threatfox = self.enrichment_services['threatfox']
        self.securitytrails = self.enrichment_services['securitytrails']
        self.virustotal = self.enrichment_services['virustotal']
        self.shodan = self.enrichment_services['shodan']
        self.alienvault = self.enrichment_services['alienvault']
        self.bgp_ranking = self.enrichment_services['bgp_ranking']
        self.urlhaus = self.enrichment_services['urlhaus']

        self.arguments = config['arguments']

        self.thresholds = config['thresholds']
        self.MAX_FREQUENCY = self.thresholds['MAX_FREQUENCY']
        self.MAX_DURATION = self.thresholds['MAX_DURATION']
        self.MAX_HTML_SIZE = self.thresholds['MAX_HTML_SIZE']

    def print_config(self):
        print(f"name: {self.name}")
        print(f"abuseipdb: {self.abuseipdb_api_key}")
        print(f"virustotal: {self.virustotal_api_key}")
        print(f"securitytrails: {self.securitytrails_api_key}")
        print(f"shodan: {self.shodan_api_key}")
        print(f"enrichment_services: {self.enrichment_services}")
        print(f"arguments: {self.arguments}")
        print(f"MAX_FREQUENCY: {self.MAX_FREQUENCY}")
        print(f"MAX_DURATION: {self.MAX_DURATION}")
        print(f"MAX_HTML_SIZE: {self.MAX_HTML_SIZE}")
