import logging
import time
import sys

class AnalystProfile:
    def __init__(self, config):

        self.name = config.get('name')
        if self.name is None:
            print(f"[{time.strftime('%H:%M:%S')}] [ERROR] The configuration file does not contain the name of the analysis ...")
            logging.error(f"The configuration file does not contain the name of the analysis")
            print("\nExiting program ...\n")
            sys.exit(1)

        self.api_keys = config.get('api_keys')
        if self.api_keys:
            self.abuseipdb_api_key = self.api_keys.get('abuseipdb')
            self.virustotal_api_key = self.api_keys.get('virustotal')
            self.securitytrails_api_key = self.api_keys.get('securitytrails')
            self.shodan_api_key = self.api_keys.get('shodan')

            if any(api_key is None for api_key in (self.abuseipdb_api_key, self.virustotal_api_key, self.securitytrails_api_key, self.shodan_api_key)):
                print(f"[{time.strftime('%H:%M:%S')}] [ERROR] Incomplete API keys are present in the configuration file ...")
                logging.error(f"Incomplete API keys are present in the configuration file")
                print("\nExiting program ...\n")
                sys.exit(1)
        else:
            print(f"[{time.strftime('%H:%M:%S')}] [ERROR] API keys are not present in the configuration file ...")
            logging.error(f"API keys are not present in the configuration file")
            print("\nExiting program ...\n")
            sys.exit(1)

        self.settings = config.get('settings')
        if self.settings:
            self.statistics_top_count = self.settings.get('statistics_top_count')
            self.chunk_size = self.settings.get('chunk_size')

            if any(setting is None for setting in (self.statistics_top_count, self.chunk_size)):
                print(f"[{time.strftime('%H:%M:%S')}] [ERROR] The configuration file does not contain general settings ...")
                logging.error(f"The configuration file does not contain general settings")
                print("\nExiting program ...\n")
                sys.exit(1)
        else:
            print(f"[{time.strftime('%H:%M:%S')}] [ERROR] Settings are not present in the configuration file ...")
            logging.error(f"Settings are not present in the configuration file")
            print("\nExiting program ...\n")
            sys.exit(1)

        self.feeds = config.get('feeds')
        if self.feeds:
            self.tor_node_list = self.feeds.get('tor_node_list')
            self.tor_exit_node_list = self.feeds.get('tor_exit_node_list')
            self.crypto_domains = self.feeds.get('crypto_domains')
            self.ja3_rules = self.feeds.get('ja3_rules')

            if any(feed is None for feed in (self.tor_node_list, self.tor_exit_node_list, self.crypto_domains, self.ja3_rules)):
                print(f"[{time.strftime('%H:%M:%S')}] [ERROR] The configuration file does not contain complete URLs for feeds ...")
                logging.error(f"The configuration file does not contain complete URLs for feeds")
                print("\nExiting program ...\n")
                sys.exit(1)
        else:
            print(f"[{time.strftime('%H:%M:%S')}] [ERROR] Feed URLs are not present in the configuration file ...")
            logging.error(f"Feed URLs are not present in the configuration file")
            print("\nExiting program ...\n")
            sys.exit(1)

        self.file_paths = config.get('file_paths')
        if self.file_paths:
            self.tor_node_list_path = self.file_paths.get('tor_node_list_path')
            self.crypto_domain_list_path = self.file_paths.get('crypto_domain_list_path')
            self.ja3_rules_path = self.file_paths.get('ja3_rules_path')
            self.domain_whitelist_path = self.file_paths.get('domain_whitelist_path')
            self.c2_http_headers_path = self.file_paths.get('c2_http_headers_path')
            self.c2_tls_certificate_values_path = self.file_paths.get('c2_tls_certificate_values_path')

            if any(file_path is None for file_path in (self.tor_node_list_path, self.crypto_domain_list_path, self.ja3_rules_path, self.domain_whitelist_path, self.c2_http_headers_path, self.c2_tls_certificate_values_path)):
                print(f"[{time.strftime('%H:%M:%S')}] [ERROR] The configuration file does not contain required file paths ...")
                logging.error(f"The configuration file does not contain required file paths")
                print("\nExiting program ...\n")
                sys.exit(1)
        else:
            print(f"[{time.strftime('%H:%M:%S')}] [ERROR] File paths are not present in the configuration file ...")
            logging.error(f"File paths are not present in the configuration file")
            print("\nExiting program ...\n")
            sys.exit(1)



        self.enrichment_services = config.get('enrichment_services')
        if self.enrichment_services:
            self.abuseipdb = self.enrichment_services.get('abuseipdb')
            self.threatfox = self.enrichment_services.get('threatfox')
            self.securitytrails = self.enrichment_services.get('securitytrails')
            self.virustotal = self.enrichment_services.get('virustotal')
            self.shodan = self.enrichment_services.get('shodan')
            self.alienvault = self.enrichment_services.get('alienvault')
            self.bgp_ranking = self.enrichment_services.get('bgp_ranking')
            self.urlhaus = self.enrichment_services.get('urlhaus')

            if any(service is None for service in (self.abuseipdb, self.threatfox, self.securitytrails, self.virustotal, self.shodan, self.alienvault, self.bgp_ranking, self.urlhaus)):
                print(f"[{time.strftime('%H:%M:%S')}] [ERROR] The configuration file does not contain complete settings for enrichment services ...")
                logging.error(f"The configuration file does not contain complete settings for enrichment services")
                print("\nExiting program ...\n")
                sys.exit(1)
        else:
            print(f"[{time.strftime('%H:%M:%S')}] [ERROR] Enrichment services are not present in the configuration file ...")
            logging.error(f"Enrichment services are not present in the configuration file")
            print("\nExiting program ...\n")
            sys.exit(1)

        # NOTE: maybe this option will not be implementd ... 
        self.arguments = config.get('arguments')

        self.sniffing = config.get('sniffing')
        if self.sniffing:
            self.interface = self.sniffing.get('interface')
            self.filter = self.sniffing.get('filter')   # optional
            self.timeout = self.sniffing.get('timeout')
            self.filename = self.sniffing.get('filename')

            if any(setting is None for setting in (self.interface, self.timeout, self.filename)):
                print(f"[{time.strftime('%H:%M:%S')}] [ERROR] The configuration file does not contain complete settings for packet sniffing ...")
                logging.error(f"The configuration file does not contain complete settings for packet sniffing")
                print("\nExiting program ...\n")
                sys.exit(1)
        else:
            print(f"[{time.strftime('%H:%M:%S')}] [ERROR] Sniffing settings are not present in the configuration file ...")
            logging.error(f"Sniffing settings are not present in the configuration file")
            print("\nExiting program ...\n")
            sys.exit(1)

        self.thresholds = config.get('thresholds')
        if self.thresholds:
            self.MAX_FREQUENCY = self.thresholds.get('MAX_FREQUENCY')
            self.MAX_DURATION = self.thresholds.get('MAX_DURATION')
            self.MAX_HTML_SIZE = self.thresholds.get('MAX_HTML_SIZE')
            self.MAX_SUBDOMAIN_LENGTH = self.thresholds.get('MAX_SUBDOMAIN_LENGTH')

            if any(thresholds is None for thresholds in (self.MAX_FREQUENCY, self.MAX_DURATION, self.MAX_HTML_SIZE, self.MAX_SUBDOMAIN_LENGTH)):
                print(f"[{time.strftime('%H:%M:%S')}] [ERROR] The configuration file does not contain complete threshold settings ...")
                logging.error(f"The configuration file does not contain complete threshold settings")
                print("\nExiting program ...\n")
                sys.exit(1)
        else:
            print(f"[{time.strftime('%H:%M:%S')}] [ERROR] Thresholds are not present in the configuration file ...")
            logging.error(f"Thresholds are not present in the configuration file")
            print("\nExiting program ...\n")
            sys.exit(1)

        # plugins are optional
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
