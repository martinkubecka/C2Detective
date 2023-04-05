class AnalystProfile:
    def __init__(self, config):
        # TODO: add checks
        self.name = config.get('name')

        # TODO: add checks
        self.api_keys = config.get('api_keys')
        self.abuseipdb_api_key = self.api_keys.get('abuseipdb')
        self.virustotal_api_key = self.api_keys.get('virustotal')
        self.securitytrails_api_key = self.api_keys.get('securitytrails')
        self.shodan_api_key = self.api_keys.get('shodan')

        # checks in place 
        self.feeds = config.get('feeds')
        self.tor_node_list = self.feeds.get('tor_node_list')
        self.tor_exit_node_list = self.feeds.get('tor_exit_node_list')
        self.crypto_domains = self.feeds.get('crypto_domains')
        self.ja3_rules = self.feeds.get('ja3_rules')

        # TODO: add checks 
        self.enrichment_services = config.get('enrichment_services')
        self.abuseipdb = self.enrichment_services.get('abuseipdb')
        self.threatfox = self.enrichment_services.get('threatfox')
        self.securitytrails = self.enrichment_services.get('securitytrails')
        self.virustotal = self.enrichment_services.get('virustotal')
        self.shodan = self.enrichment_services.get('shodan')
        self.alienvault = self.enrichment_services.get('alienvault')
        self.bgp_ranking = self.enrichment_services.get('bgp_ranking')
        self.urlhaus = self.enrichment_services.get('urlhaus')

        # TODO: add checks
        self.arguments = config.get('arguments')

        # TODO: add checks
        self.sniffing = config.get('sniffing') 
        self.interface = self.sniffing.get('interface')
        self.filter = self.sniffing.get('filter')
        self.timeout = self.sniffing.get('timeout')

        # TODO: add checks
        self.thresholds = config.get('thresholds')
        self.MAX_FREQUENCY = self.thresholds.get('MAX_FREQUENCY')
        self.MAX_DURATION = self.thresholds.get('MAX_DURATION')
        self.MAX_HTML_SIZE = self.thresholds.get('MAX_HTML_SIZE')
        self.MAX_SUBDOMAIN_LENGTH = self.thresholds.get('MAX_SUBDOMAIN_LENGTH')

        # check is not required, because plugins are optional
        self.plugins = config.get('plugins')

    def print_config(self):
        print(f"name: {self.name}")
        print(f"abuseipdb: {self.abuseipdb_api_key}")
        print(f"virustotal: {self.virustotal_api_key}")
        print(f"securitytrails: {self.securitytrails_api_key}")
        print(f"shodan: {self.shodan_api_key}")
        print(f"tor_node_list: {self.tor_node_list}")
        print(f"tor_exit_node_list: {self.tor_exit_node_list}")
        print(f"crypto_domains: {self.crypto_domains}")
        print(f"ja3_rules: {self.ja3_rules}")
        print(f"enrichment_services: {self.enrichment_services}")
        print(f"arguments: {self.arguments}")
        print(f"sniffing: {self.sniffing}")
        print(f"MAX_FREQUENCY: {self.MAX_FREQUENCY}")
        print(f"MAX_DURATION: {self.MAX_DURATION}")
        print(f"MAX_HTML_SIZE: {self.MAX_HTML_SIZE}")
        print(f"MAX_SUBDOMAIN_LENGTH: {self.MAX_SUBDOMAIN_LENGTH}")
        print(f"plugins: {self.plugins}")

