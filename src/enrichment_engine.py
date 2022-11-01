import requests
import json
import shodan
import os
import sys
from ipaddress import ip_address, IPv4Address
# from censys.search import CensysHosts
import logging
import time


class EnrichmentEngine:
    def __init__(self, analyst_profile, packet_parser):
        self.logger = logging.getLogger(__name__)
        self.analyst_profile = analyst_profile
        self.packet_parser = packet_parser

        self.report_dir = f"{os.path.dirname(os.path.realpath(sys.argv[0]))}/reports"

        self.abuseipdb_api_url = 'https://api.abuseipdb.com/api/v2/check'
        self.securitytrails_api_url = "https://api.securitytrails.com/v1/"
        self.virustotal_api_url = "https://www.virustotal.com/vtapi/v2/"
        self.shodan_api_url = "https://api.shodan.io/"
        self.alientvault_api_url = "https://otx.alienvault.com/api/v1/indicators/"
        self.bgp_ranking_api_url = "https://bgpranking-ng.circl.lu/"

    # CHECK Endpoint : https://docs.abuseipdb.com/#check-endpoint
    def query_abuseipdb(self, ip: str = None):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] ABUSEIPDB")
        self.logger.info(f"ABUSEIPDB")
        try:
            if is_ip_address(ip):
                if not ipaddress.ip_address(ip).is_private:
                    querystring = {
                        'ipAddress': ip,
                        'maxAgeInDays': '90'
                    }
                    headers = {
                        'Accept': 'application/json',
                        'Key': self.analyst_profile.abuseipdb_api_key,
                        'verbose': ''
                    }

                    print(f"[{time.strftime('%H:%M:%S')}] [INFO] Fetching data for '{ip}'")
                    self.logger.info(f"Fetching data for '{ip}'")
                    response = requests.request(
                        method='GET', url=self.abuseipdb_api_url, headers=headers, params=querystring)

                    if response.status_code == 401:
                        print(
                            f"[{time.strftime('%H:%M:%S')}] [ERROR] Authentication failed. Your API key is either missing, incorrect, or revoked. Note: The APIv2 key differs from the APIv1 key.")
                        self.logger.error(
                            "Authentication failed. Your API key is either missing, incorrect, or revoked. Note: The APIv2 key differs from the APIv1 key.")
                        return
                    else:
                        dict_response = json.loads(response.text)
                        json_object = json.dumps(dict_response, indent=4)

        except Exception as e:
            print(
                f"[{time.strftime('%H:%M:%S')}] [ERROR] Error ocurred while quering the AbuseIPDB's API")
            self.logger.error(
                "Error ocurred while quering the AbuseIPDB's API", exc_info=True)
            return

        self.output_report("abuseipdb", json_object)

    # API Reference : https://docs.securitytrails.com/reference/ping
    # https://docs.securitytrails.com/docs
    def query_securitytrails(self, keyword: str = None):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] SECURITYTRAILS")
        self.logger.info(f"SECURITYTRAILS")
        headers = {"accept": "application/json",
                   'APIKEY': self.analyst_profile.securitytrails_api_key}
        try:
            # check API access
            url = self.securitytrails_api_url + "ping"
            response = requests.get(url, headers=headers)
            decoded_response = json.loads(response.text)

            if "message" in decoded_response:
                print(f"[!] {decoded_response['message']}")
                self.logger.error(
                    f"{decoded_response['message']}", exc_info=True)
                return

            if not is_ip_address(keyword):  # input is a domain ; no API for IP lookups ...
                dict_response = []
                print(
                    f"[{time.strftime('%H:%M:%S')}] [INFO] Fetching current DNS details (a, aaaa, mx, ns, soa, txt) for '{keyword}'")
                self.logger.info(f"Fetching current DNS details (a, aaaa, mx, ns, soa, txt) for '{keyword}'")
                # get details for current_dns (a, aaaa, mx, ns, soa, txt)
                url = f"{self.securitytrails_api_url}domain/{keyword}"
                response = requests.get(url, headers=headers)
                dict_response.append(response.json())

                # get subdomain_count, subdomains list
                print(f"[{time.strftime('%H:%M:%S')}] [INFO] Fetching subdomain list for '{keyword}'")
                self.logger.info(f"Fetching subdomain list for '{keyword}'")
                url = f"{self.securitytrails_api_url}domain/{keyword}/subdomains?children_only=false&include_inactive=true"
                response = requests.get(url, headers=headers)
                dict_response.append(response.json())

                # returns tags for a given hostname
                print(f"[{time.strftime('%H:%M:%S')}] [INFO] Fetching tags for '{keyword}'")
                self.logger.info(f"Fetching tags for '{keyword}'")
                url = f"{self.securitytrails_api_url}domain/{keyword}/tags"
                response = requests.get(url, headers=headers)
                dict_response.append(response.json())

                # historical information about the given hostname parameter
                record_types = ['a', 'aaaa', 'mx', 'ns', 'soa', 'txt']
                record_types_response = []
                for record_type in record_types:
                    print(
                        f"[{time.strftime('%H:%M:%S')}] [INFO] Fetching historical '{record_type}' record from DNS details for '{keyword}'")
                    self.logger.info(f"Fetching historical '{record_type}' record from DNS details for '{keyword}'")
                    url = f"{self.securitytrails_api_url}history/{keyword}/dns/{record_type}"
                    # url = f"{self.securitytrails_api_url}history/{keyword}/dns/{record_type}?page=1"    # there may be more pages ...
                    response = requests.get(url, headers=headers)
                    record_types_response.append(response.json())

                dict_response.append(record_types_response)
                json_object = json.dumps(dict_response, indent=4)

        except Exception as e:
            print(
                f"[{time.strftime('%H:%M:%S')}] [ERROR] Error ocurred while quering the SecurityTrail's API")
            self.logger.error(
                "Error ocurred while quering the SecurityTrail's API", exc_info=True)
            return

        self.output_report("securitytrails", json_object)

    # API Reference : https://developers.virustotal.com/v2.0/reference/getting-started
    def query_virustotal(self, keyword: str = None):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] VIRUSTOTAL")
        self.logger.info(f"VIRUSTOTAL")
        try:
            dict_response = []
            if not is_ip_address(keyword):  # input is a domain
                # retrieves a domain report
                # https://developers.virustotal.com/v2.0/reference/domain-report
                print(f"[{time.strftime('%H:%M:%S')}] [INFO] Retrieving domain report for '{keyword}'")
                self.logger.info(f"Retrieving domain report for '{keyword}'")
                url = f"{self.virustotal_api_url}domain/report?apikey={self.analyst_profile.virustotal_api_key}&domain={keyword}"
                response = requests.get(url)
                dict_response.append(response.json())
                # json_object = json.dumps(dict_response, indent=4)
            else:
                # retrieve an IP address report
                # https://developers.virustotal.com/v2.0/reference/ip-address-report
                print(f"[{time.strftime('%H:%M:%S')}] [INFO] Retrieving IP address report for '{keyword}'")
                self.logger.info(f"Retrieving IP address report for '{keyword}'")
                url = f"{self.virustotal_api_url}ip-address/report?apikey={self.analyst_profile.virustotal_api_key}&ip={keyword}"
                response = requests.get(url)
                dict_response.append(response.json())
                # json_object = json.dumps(dict_response, indent=4)

            # retrieve URL scan reports
            # https://developers.virustotal.com/v2.0/reference/url-report
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] Retrieving scan reports for '{keyword}'")
            self.logger.info(f"Retrieving scan reports for '{keyword}'")
            url = f"{self.virustotal_api_url}url/report?apikey={self.analyst_profile.virustotal_api_key}&resource={keyword}&scan=1"
            response = requests.get(url)
            dict_response.append(response.json())
            # json_object = json.dumps(dict_response, indent=4)

            json_object = json.dumps(dict_response, indent=4)

        except Exception as e:
            print(
                f"[{time.strftime('%H:%M:%S')}] [ERROR] Error ocurred while quering the VirusTotal's API")
            self.logger.error(
                "Error ocurred while quering the VirusTotal's API", exc_info=True)
            return

        self.output_report("virustotal", json_object)

    # API Reference: https://shodan.readthedocs.io/en/latest/examples/basic-search.html
    # used package: https://github.com/achillean/shodan-python
    # code source : https://subscription.packtpub.com/book/networking-&-servers/9781784392932/1/ch01lvl1sec11/gathering-information-using-the-shodan-api
    def query_shodan(self, keyword: str = None):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] SHODAN")
        self.logger.info(f"SHODAN")
        api = shodan.Shodan(self.analyst_profile.shodan_api_key)
        target = keyword
        try:
            if not is_ip_address(target):  # input is a domain
                print(f"[{time.strftime('%H:%M:%S')}] [INFO] Resolving '{keyword}' to an IP address")
                self.logger.info(f"Resolving '{keyword}' to an IP address")
                url = f"{self.shodan_api_url}dns/resolve?hostnames={target}&key={self.analyst_profile.shodan_api_key}"
                # resolve target domain to an IP address
                response = requests.get(url)
                decoded_response = json.loads(response.text)
                # print(json.dumps(decoded_response, indent=4))
                target = decoded_response[keyword]
                print(f"[{time.strftime('%H:%M:%S')}] [INFO] Resolved '{keyword}' to '{target}'")
                self.logger.info(f"Resolved '{keyword}' to '{target}'")

            # execute a Shodan search on the resolved IP
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] Executing search query and retrieving API's response")
            self.logger.info(f"Executing search query and retrieving API's response")
            result = api.host(target)
            decoded_response = json.dumps(result, indent=4)

            # print("[*] General Information")
            # print(f"IP: {result['ip_str']}")
            # print(f"Hostnames: {result['hostnames']}")
            # print(f"Domains: {result['domains']}")
            # print(f"Country: {result['country_name']}")
            # print(f"City: {result['city']}")
            # print(f"Organization: {result['org']}")
            # print(f"ISP: {result['isp']}")
            # print(f"ASN: {result['asn']}\n")
            # print(f"Operating System: {result['os']}")

            # print all banners
            # print("[*] Open ports")
            # print(f"{result['ports']}\n")
            # for item in result['data']:
            #     print(f"Port: {item['port']}")
            #     print(f"Banner: {item['data']}")

            # print vuln information
            # if "vulns" in result:   # there may not be any vulns
            #     print("[*] Vulnerabilities")
            #     print(result['vulns'])  # prints only list of CVEs
            # slow approach
            # for item in result['vulns']:
            # CVE = item.replace('!', '')
            # print(f"Vulns: {item}")
            # exploits = api.exploits.search(CVE)
            # for item in exploits['matches']:
            #     if item.get('cve')[0] == CVE:
            #         print(f"{item.get('description')}")

        except Exception as e:
            print(
                f"[{time.strftime('%H:%M:%S')}] [ERROR] Error ocurred while quering the Shodan's API")
            self.logger.error(
                "Error ocurred while quering the Shodan's API", exc_info=True)
            return

        self.output_report("shodan", decoded_response)

    # source : https://www.circl.lu/projects/bgpranking/
    def query_bgp_ranking(self, asn: str = None, date: str = None):
        '''Launch a query.
            :param asn: ASN to lookup
            :param date: Exact date to lookup. Fallback to most recent available.
        '''
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] BGP RANKING")
        self.logger.info(f"BGP RANKING")
        # ranking the ASN from the most malicious to the less malicious ASN
        try:
            if asn:
                to_query = {'asn': asn}
                if date:
                    to_query['date'] = date
                print(f"[{time.strftime('%H:%M:%S')}] [INFO] Retrieving ASN ranking for '{asn}'")
                self.logger.info(f"Retrieving ASN ranking for '{asn}'")
                response = requests.post(
                    f"{self.bgp_ranking_api_url}/json/asn", data=json.dumps(to_query))
                dict_response = json.loads(response.text)
                json_object = json.dumps(dict_response, indent=4)
            else:
                print(f"[{time.strftime('%H:%M:%S')}] [WARNING] No ASN was provided. Skipping BGP ranking ...")
                self.logger.warning(msg)(f"No ASN was provided. Skipping BGP ranking ...")
                return

        except Exception as e:
            print(
                f"[{time.strftime('%H:%M:%S')}] [ERROR] Error ocurred while quering the CIRCL's API")
            self.logger.error(
                "Error ocurred while quering the CIRCL's API", exc_info=True)
            return

        self.output_report("bgp_ranking", json_object)

    # AlienVault External API documentation : https://otx.alienvault.com/assets/static/external_api.html
    def query_alientvault(self, target: str = None):

        ip_type = get_ip_type(target)
        sections = ["general", "geo", "reputation", "url_list", "passive_dns", "malware", "http_scans"]
        dict_response = []
        try:
            if ip_type == "IPv4":
                for section in sections:
                    print(f"[{time.strftime('%H:%M:%S')}] [INFO] Fetching '{section}' section of indicators for '{target}'")
                    response = requests.get(
                        f'{self.alientvault_api_url}IPv4/{target}/{section}')
                    dict_response.append(response.json())
    
                json_object = json.dumps(dict_response, indent=4)

            elif ip_type == "IPv6":
                for section in sections:
                    print(f"[{time.strftime('%H:%M:%S')}] [INFO] Fetching '{section}' section of indicators for '{target}'")
                    response = requests.get(f'{self.alientvault_api_url}IPv6/{target}/{section}')
                    dict_response.append(response.json())

                json_object = json.dumps(dict_response, indent=4)

            else:   # target is a domain
                for section in sections:
                    print(f"[{time.strftime('%H:%M:%S')}] [INFO] Fetching '{section}' section of indicators for '{target}'")
                    response = requests.get(f'{self.alientvault_api_url}domain/{target}/{section}')
                    dict_response.append(response.json())

                json_object = json.dumps(dict_response, indent=4)
        
        except Exception as e:
            print(
                f"[{time.strftime('%H:%M:%S')}] [ERROR] Error ocurred while quering the AlienVault's API")
            self.logger.error(
                "Error ocurred while quering the AlienVault's API", exc_info=True)
            return
        
        self.output_report("alientvault", json_object)


    # API Reference: https://censys-python.readthedocs.io/en/stable/quick-start.html
    # https://github.com/censys/censys-python
    # def query_censys(self):
    #     print(f"\n~~~~~~~~~~~~~~~ CENSYS ~~~~~~~~~~~~~~~")
    #     # to configure your search credentials run censys config or set
    #     # both CENSYS_API_ID and CENSYS_API_SECRET environment variables
    #     # $ censys config OR export CENSYS_API_ID=<your-api-id> ; export CENSYS_API_SECRET=<your-api-secret>
    #     h = CensysHosts()
    #     host = h.view("8.8.8.8")
    #     print(host)

    def output_report(self, service_name, json_object):
        if not os.path.isdir(self.report_dir):
            print(
                f"[{time.strftime('%H:%M:%S')}] [INFO] Creating '{self.report_dir}' for storing analysis reports")
            self.logger.info(
                f"Creating '{self.report_dir}' for storing analysis reports")
            os.mkdir(self.report_dir)

        report_output_path = f"{self.report_dir}/{service_name}.json"
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Writing report to '{report_output_path}'")
        self.logger.info(f"Writing report to '{report_output_path}'")
        with open(report_output_path, "w") as output:
            output.write(json_object)


def get_ip_type(ip: str):
    try:
        return "IPv4" if type(ip_address(ip)) is IPv4Address else "IPv6"
    except ValueError:
        return "Invalid"

def is_ip_address(string):
    flag = False
    if ("." in string):
        elements_array = string.strip().split(".")
        if (len(elements_array) == 4):
            for i in elements_array:
                if (i.isnumeric() and int(i) >= 0 and int(i) <= 255):
                    flag = True
                else:
                    flag = False
                    break
    return flag
