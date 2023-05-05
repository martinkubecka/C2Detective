import requests
import json
import shodan
from ipaddress import ip_address, IPv4Address
import logging
import time


def get_ip_address_type(target):
    try:
        return "IPv4" if type(ip_address(target)) is IPv4Address else "IPv6"
    except ValueError:
        return "Invalid"


def is_target_ip_address(target):
    is_ip = False
    if "." in target:
        elements_array = target.strip().split(".")
        if len(elements_array) == 4:
            for i in elements_array:
                if i.isnumeric() and 0 <= int(i) <= 255:
                    is_ip = True
                else:
                    is_ip = False
                    break
    return is_ip


class EnrichmentEngine:
    def __init__(self, output_dir, api_keys, api_urls, enrichment_services, detected_iocs):
        self.logger = logging.getLogger(__name__)
        self.report_dir = output_dir

        self.api_keys = api_keys
        self.abuseipdb_api_key = self.api_keys.get('abuseipdb')
        self.virustotal_api_key = self.api_keys.get('virustotal')
        self.shodan_api_key = self.api_keys.get('shodan')

        self.api_urls = api_urls
        self.abuseipdb_api_url = self.api_urls.get('abuseipdb')
        self.threatfox_api_url = self.api_urls.get('threatfox')
        self.virustotal_api_url = self.api_urls.get('virustotal')
        self.shodan_api_url = self.api_urls.get('shodan')
        self.alienvault_api_url = self.api_urls.get('alienvault')
        self.urlhaus_api_url = self.api_urls.get('urlhaus')

        self.detected_iocs = detected_iocs
        self.ip_addresses = self.detected_iocs.get('aggregated_ip_addresses')
        self.domain_names = self.detected_iocs.get('aggregated_domain_names')
        self.urls = self.detected_iocs.get('aggregated_urls')

        self.enriched_iocs = {'ip_addresses': {}, 'domain_names': {}, 'urls': {}}

        self.enabled_enrichment_services = enrichment_services

    def enrich_detected_iocs(self):
        if self.ip_addresses:
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] Enriching detected IP address IoCs ...")
            self.logger.info(f"Enriching detected IP address IoCs")
            for ip_addr in self.ip_addresses:
                self.enriched_iocs['ip_addresses'][ip_addr] = {}

                if self.enabled_enrichment_services.get('abuseipdb'):
                    self.enriched_iocs['ip_addresses'][ip_addr]['abuseipdb'] = self.query_abuseipdb(ip_addr)
                else:
                    self.enriched_iocs['ip_addresses'][ip_addr]['abuseipdb'] = {}

                if self.enabled_enrichment_services.get('threatfox'):
                    self.enriched_iocs['ip_addresses'][ip_addr]['threatfox'] = self.query_threatfox(ip_addr)
                else:
                    self.enriched_iocs['ip_addresses'][ip_addr]['threatfox'] = {}

                if self.enabled_enrichment_services.get('virustotal'):
                    self.enriched_iocs['ip_addresses'][ip_addr]['virustotal'] = self.query_virustotal(ip_addr)
                else:
                    self.enriched_iocs['ip_addresses'][ip_addr]['virustotal'] = {}

                if self.enabled_enrichment_services.get('shodan'):
                    self.enriched_iocs['ip_addresses'][ip_addr]['shodan'] = self.query_shodan(ip_addr)
                else:
                    self.enriched_iocs['ip_addresses'][ip_addr]['shodan'] = {}

                if self.enabled_enrichment_services.get('alienvault'):
                    self.enriched_iocs['ip_addresses'][ip_addr]['alienvault'] = self.query_alienvault(ip_addr)
                else:
                    self.enriched_iocs['ip_addresses'][ip_addr]['alienvault'] = {}

                if self.enabled_enrichment_services.get('urlhaus'):
                    ip_type = get_ip_address_type(ip_addr)
                    if not ip_type == "IPv6":
                        self.enriched_iocs['ip_addresses'][ip_addr]['urlhaus'] = self.query_urlhaus(ip_addr, "host")
                    else:
                        self.enriched_iocs['ip_addresses'][ip_addr]['urlhaus'] = {}
                else:
                    self.enriched_iocs['ip_addresses'][ip_addr]['urlhaus'] = {}

        if self.domain_names:
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] Enriching detected domain name IoCs ...")
            self.logger.info(f"Enriching detected domain name IoCs")
            for domain_name in self.domain_names:
                self.enriched_iocs['domain_names'][domain_name] = {}

                if self.enabled_enrichment_services.get('abuseipdb'):
                    self.enriched_iocs['domain_names'][domain_name]['abuseipdb'] = self.query_abuseipdb(domain_name)
                else:
                    self.enriched_iocs['domain_names'][domain_name]['abuseipdb'] = {}

                if self.enabled_enrichment_services.get('threatfox'):
                    self.enriched_iocs['domain_names'][domain_name]['threatfox'] = self.query_threatfox(domain_name)
                else:
                    self.enriched_iocs['domain_names'][domain_name]['threatfox'] = {}

                if self.enabled_enrichment_services.get('virustotal'):
                    self.enriched_iocs['domain_names'][domain_name]['virustotal'] = self.query_virustotal(domain_name)
                else:
                    self.enriched_iocs['domain_names'][domain_name]['virustotal'] = {}

                if self.enabled_enrichment_services.get('shodan'):
                    self.enriched_iocs['domain_names'][domain_name]['shodan'] = self.query_shodan(domain_name)
                else:
                    self.enriched_iocs['domain_names'][domain_name]['shodan'] = {}

                if self.enabled_enrichment_services.get('alienvault'):
                    self.enriched_iocs['domain_names'][domain_name]['alienvault'] = self.query_alienvault(domain_name)
                else:
                    self.enriched_iocs['domain_names'][domain_name]['alienvault'] = {}

                if self.enabled_enrichment_services.get('urlhaus'):
                    self.enriched_iocs['domain_names'][domain_name]['urlhaus'] = self.query_urlhaus(domain_name, "host")
                else:
                    self.enriched_iocs['domain_names'][domain_name]['urlhaus'] = {}

        if self.urls:
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] Enriching detected URL IoCs ...")
            self.logger.info(f"Enriching detected URL IoCs")
            for url in self.urls:
                self.enriched_iocs['urls'][url] = {}

                self.enriched_iocs['urls'][url]['abuseipdb'] = {}

                if self.enabled_enrichment_services.get('threatfox'):
                    self.enriched_iocs['urls'][url]['threatfox'] = self.query_threatfox(url)
                else:
                    self.enriched_iocs['urls'][url]['threatfox'] = {}

                if self.enabled_enrichment_services.get('virustotal'):
                    self.enriched_iocs['urls'][url]['virustotal'] = self.query_virustotal(url)
                else:
                    self.enriched_iocs['urls'][url]['virustotal'] = {}

                self.enriched_iocs['urls'][url]['shodan'] = {}

                self.enriched_iocs['urls'][url]['alienvault'] = {}

                if self.enabled_enrichment_services.get('urlhaus'):
                    self.enriched_iocs['urls'][url]['urlhaus'] = self.query_urlhaus(url, "url")
                else:
                    self.enriched_iocs['urls'][url]['urlhaus'] = {}

        return self.enriched_iocs

    # API Reference : https://docs.abuseipdb.com/#check-endpoint
    def query_abuseipdb(self, target):
        try:
            querystring = {
                'ipAddress': target,
                'maxAgeInDays': '90',
                'verbose': ''
            }
            headers = {
                'Accept': 'application/json',
                'Key': self.abuseipdb_api_key,
            }

            # print(f"[{time.strftime('%H:%M:%S')}] [INFO] AbuseIPDB : Fetching data for '{target}'")
            self.logger.info(f"AbuseIPDB : Fetching data for '{target}'")
            response = requests.request(
                method='GET', url=self.abuseipdb_api_url, headers=headers, params=querystring)

            if response.status_code == 401:
                print(
                    f"[{time.strftime('%H:%M:%S')}] [ERROR] Authentication failed. Your API key is either missing, incorrect, or revoked. Note: The APIv2 key differs from the APIv1 key.")
                self.logger.error(
                    "Authentication failed. Your API key is either missing, incorrect, or revoked. Note: The APIv2 key differs from the APIv1 key.")
                return {}
            else:
                enriched_data = json.loads(response.text)
                return enriched_data

        except Exception as e:
            print(f"[{time.strftime('%H:%M:%S')}] [ERROR] Error occurred while querying the AbuseIPDB's API")
            self.logger.error("Error occurred while querying the AbuseIPDB's API", exc_info=True)
            return {}

    # API Reference : https://threatfox.abuse.ch/api/
    def query_threatfox(self, target):
        try:
            data = {"query": "search_ioc",
                    "search_term": target
                    }

            # print(f"[{time.strftime('%H:%M:%S')}] [INFO] ThreatFox : Fetching data for '{ip}'")
            self.logger.info(f"ThreatFox : Fetching data for '{target}'")
            response = requests.post(
                self.threatfox_api_url, data=json.dumps(data))
            enriched_data = json.loads(response.text)

            if enriched_data.get('query_status') == "ok":
                return enriched_data
            else:
                return {}

        except Exception as e:
            print(f"[{time.strftime('%H:%M:%S')}] [ERROR] Error occurred while querying the ThreatFox's API")
            self.logger.error("Error occurred while querying the ThreatFox's API", exc_info=True)
            return {}

    # API Reference : https://developers.virustotal.com/v2.0/reference/getting-started
    def query_virustotal(self, target):
        try:
            enriched_data = {}

            # retrieve URL scan reports
            # https://developers.virustotal.com/v2.0/reference/url-report
            self.logger.info(
                f"Virustotal : Retrieving scan reports for '{target}'")
            url = f"{self.virustotal_api_url}url/report?apikey={self.virustotal_api_key}&resource={target}&scan=1"
            response = requests.get(url)
            if response.status_code == 204:
                print(
                    f"[{time.strftime('%H:%M:%S')}] [WARNING] Virustotal API request rate limit exceeded")
                self.logger.warning(
                    f"Virustotal API request rate limit exceeded")
                return {}
            else:
                enriched_data = json.loads(response.text)

            if is_target_ip_address(target):  # input is a domain
                # https://developers.virustotal.com/v2.0/reference/ip-address-report
                # print(f"[{time.strftime('%H:%M:%S')}] [INFO] Virustotal : Retrieving IP address report for '{keyword}'")
                self.logger.info(
                    f"Virustotal : Retrieving IP address report for '{target}'")
                url = f"{self.virustotal_api_url}ip-address/report?apikey={self.virustotal_api_key}&ip={target}"
                response = requests.get(url)
                if response.status_code == 204:
                    print(
                        f"[{time.strftime('%H:%M:%S')}] [WARNING] Virustotal API request rate limit exceeded")
                    self.logger.warning(
                        f"Virustotal API request rate limit exceeded")
                    return
                else:
                    enriched_data.update(response.json())
            else:
                # https://developers.virustotal.com/v2.0/reference/domain-report
                # print(f"[{time.strftime('%H:%M:%S')}] [INFO] Virustotal : Retrieving domain report for '{keyword}'")
                self.logger.info(
                    f"Virustotal : Retrieving domain report for '{target}'")
                url = f"{self.virustotal_api_url}domain/report?apikey={self.virustotal_api_key}&domain={target}"
                response = requests.get(url)
                if response.status_code == 204:
                    print(
                        f"[{time.strftime('%H:%M:%S')}] [WARNING] Virustotal API request rate limit exceeded")
                    self.logger.warning(f"API request rate limit exceeded")
                    return {}
                else:
                    enriched_data.update(response.json())

            return enriched_data

        except Exception as e:
            print(
                f"[{time.strftime('%H:%M:%S')}] [ERROR] Error ocurred while querying the VirusTotal's API")
            self.logger.error(
                "Error ocurred while querying the VirusTotal's API", exc_info=True)
            return {}

    # API Reference: https://shodan.readthedocs.io/en/latest/examples/basic-search.html
    def query_shodan(self, target):
        # Used package: https://github.com/achillean/shodan-python
        # Code source : https://subscription.packtpub.com/book/networking-&-servers/9781784392932/1/ch01lvl1sec11/gathering-information-using-the-shodan-api
        try:
            shodan_api = shodan.Shodan(self.shodan_api_key)

            if not is_target_ip_address(target):  # input is a domain
                # print(f"[{time.strftime('%H:%M:%S')}] [INFO] Shodan : Resolving '{target}' to an IP address")
                self.logger.info(
                    f"Shodan : Resolving '{target}' to an IP address")
                url = f"{self.shodan_api_url}dns/resolve?hostnames={target}&key={self.shodan_api_key}"
                # resolve target domain to an IP address
                response = requests.get(url)
                decoded_response = json.loads(response.text)
                # print(json.dumps(decoded_response, indent=4))
                ip_addr = decoded_response[target]
                if ip_addr:
                    # print(f"[{time.strftime('%H:%M:%S')}] [INFO] Shodan : Resolved '{target}' to '{ip_addr}'")
                    self.logger.info(f"Shodan : Resolved '{target}' to '{ip_addr}'")
                    target = ip_addr
                else:
                    print(
                        f"[{time.strftime('%H:%M:%S')}] [WARNING] Shodan : Failed to resolved '{target}' to an IP address")
                    self.logger.warning(f"Shodan : Failed to resolved '{target}' to an IP address")
                    return {}

            # execute a Shodan search query for IP
            # print(f"[{time.strftime('%H:%M:%S')}] [INFO] Shodan : Executing search query for '{target}' and retrieving API's response")
            self.logger.info(f"Shodan : Executing search query for '{target}' and retrieving API's response")

            try:
                enriched_data = shodan_api.host(target)
            except shodan.APIError as error:
                # print(f"[{time.strftime('%H:%M:%S')}] [INFO] Shodan : No results found for '{target}'")
                self.logger.info(f"Shodan : No results found for '{target}'")
                return {}

            return enriched_data

        except Exception as e:
            print(f"[{time.strftime('%H:%M:%S')}] [ERROR] Error occurred while querying the Shodan's API")
            self.logger.error("Error occurred while querying the Shodan's API", exc_info=True)
            return {}

    # API Reference : https://otx.alienvault.com/assets/static/external_api.html
    def query_alienvault(self, target):
        try:
            ip_type = get_ip_address_type(target)
            sections = ["general", "geo", "url_list", "passive_dns", "malware", "http_scans"]
            enriched_data = {}

            if ip_type == "IPv4":
                for section in sections:
                    # print(f"[{time.strftime('%H:%M:%S')}] [INFO] AlienVault : Fetching '{section}' section of indicators for '{target}'")
                    self.logger.info(f"AlienVault : Fetching '{section}' section of indicators for '{target}'")
                    response = requests.get(f'{self.alienvault_api_url}IPv4/{target}/{section}')
                    enriched_data[section] = json.loads(response.text)

            elif ip_type == "IPv6":
                for section in sections:
                    # print(f"[{time.strftime('%H:%M:%S')}] [INFO] AlienVault : Fetching '{section}' section of indicators for '{target}'")
                    self.logger.info(f"AlienVault : Fetching '{section}' section of indicators for '{target}'")
                    response = requests.get(f'{self.alienvault_api_url}IPv6/{target}/{section}')
                    enriched_data[section] = json.loads(response.text)

            else:  # target is a domain
                for section in sections:
                    # print(f"[{time.strftime('%H:%M:%S')}] [INFO] AlienVault : Fetching '{section}' section of indicators for '{target}'")
                    self.logger.info(f"AlienVault : Fetching '{section}' section of indicators for '{target}'")
                    response = requests.get(f'{self.alienvault_api_url}domain/{target}/{section}')
                    enriched_data[section] = json.loads(response.text)

            return enriched_data

        except Exception as e:
            print(f"[{time.strftime('%H:%M:%S')}] [ERROR] Error occurred while querying the AlienVault's API")
            self.logger.error("Error occurred while querying the AlienVault's API", exc_info=True)
            return {}

    # API Reference : https://urlhaus-api.abuse.ch
    def query_urlhaus(self, target, endpoint):
        try:
            enriched_data = {}

            if endpoint == "url":
                # query url information : https://urlhaus-api.abuse.ch/#urlinfo
                urlhaus_api = f"{self.urlhaus_api_url}url/"
                data = {'url': target}

            elif endpoint == "host":
                # query host information : https://urlhaus-api.abuse.ch/#hostinfo
                urlhaus_api = f"{self.urlhaus_api_url}host/"
                data = {'host': target}
            else:
                return {}

            # print(f"[{time.strftime('%H:%M:%S')}] [INFO] URLhaus : Querying database for {target} ...")
            self.logger.info(f"URLhaus : Querying database for {target} ...")

            response = requests.post(urlhaus_api, data=data)
            enriched_data = json.loads(response.text)

            if enriched_data.get('query_status') == "ok":
                return enriched_data
            else:
                # print(f"[{time.strftime('%H:%M:%S')}] [WARNING] URLhaus : No result or illegal search term")
                self.logger.warning(
                    f"URLhaus : No result or illegal search term (API response: '{enriched_data.get('query_status')})'")
                return {}

        except Exception as e:
            print(f"[{time.strftime('%H:%M:%S')}] [ERROR] Error occurred while querying the URLhaus's API")
            self.logger.error("Error occurred while querying the URLhaus's API", exc_info=True)
        return {}
