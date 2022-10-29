import requests
import json
import shodan
import os
import sys
# from censys.search import CensysHosts


class Enrichment:
    def __init__(self, analyst_profile, packet_parser):
        self.analyst_profile = analyst_profile
        self.packet_parser = packet_parser

        self.report_dir = f"{os.path.dirname(os.path.realpath(sys.argv[0]))}/reports"

        self.abuseipdb_api_url = 'https://api.abuseipdb.com/api/v2/check'
        self.securitytrails_api_url = "https://api.securitytrails.com/v1/"
        self.virustotal_api_url = "https://www.virustotal.com/vtapi/v2/"
        self.shodan_api_url = "https://api.shodan.io/"

    # CHECK Endpoint : https://docs.abuseipdb.com/#check-endpoint
    def query_abuseipdb(self, ip_list):
        print(f"\n~~~~~~~~~~~~~~~ ABUSEIPDB ~~~~~~~~~~~~~~~")
        for ip in ip_list:
            querystring = {
                'ipAddress': ip,
                'maxAgeInDays': '90'
            }

            headers = {
                'Accept': 'application/json',
                'Key': self.analyst_profile.abuseipdb_api_key,
                'verbose': ''
            }

            response = requests.request(
                method='GET', url=self.abuseipdb_api_url, headers=headers, params=querystring)

            # maybe throw away those with abuseConfidenceScore == 0
            decoded_response = json.loads(response.text)
            print(json.dumps(decoded_response, sort_keys=True, indent=4))

    # API Reference : https://docs.securitytrails.com/reference/ping
    # https://docs.securitytrails.com/docs
    # CHECK IF KEYWORD IS IP OR DOMAIN
    def query_securitytrails(self, keyword="securitytrails.com"):
        print(f"\n~~~~~~~~~~~~~~~ SECURITYTRAILS ~~~~~~~~~~~~~~~")
        headers = {"accept": "application/json",
                   'APIKEY': self.analyst_profile.securitytrails_api_key}
        try:
            # check API access
            url = self.securitytrails_api_url + "ping"
            response = requests.get(url, headers=headers)
            decoded_response = json.loads(response.text)

            if "message" in decoded_response:
                print(f"[!] {decoded_response['message']}")
                return

            # get details for current_dns (a, aaaa, mx, ns, soa, txt)
            url = f"{self.securitytrails_api_url}domain/{keyword}"
            response = requests.get(url, headers=headers)
            decoded_response = json.loads(response.text)
            print(json.dumps(decoded_response, indent=4))

            # get subdomain_count, subdomains list
            url = f"{self.securitytrails_api_url}domain/{keyword}/subdomains?children_only=false&include_inactive=true"
            response = requests.get(url, headers=headers)
            decoded_response = json.loads(response.text)
            print(json.dumps(decoded_response, indent=4))

            # returns tags for a given hostname
            url = f"{self.securitytrails_api_url}domain/{keyword}/tags"
            response = requests.get(url, headers=headers)
            decoded_response = json.loads(response.text)
            print(json.dumps(decoded_response, indent=4))

            # historical information about the given hostname parameter
            record_types = ['a', 'aaaa', 'mx', 'ns', 'soa', 'txt']
            for record_type in record_types:
                url = f"{self.securitytrails_api_url}history/{keyword}/dns/{record_type}"
                # url = f"{self.securitytrails_api_url}history/{keyword}/dns/{record_type}?page=1"    # there may be more pages ...
                response = requests.get(url, headers=headers)
                decoded_response = json.loads(response.text)
                print(json.dumps(decoded_response, indent=4))
        except Exception as e:
            print(f"[!] Error ocurred while quering the SecurityTrail's API")
            print(e)

    # API Reference : https://developers.virustotal.com/v2.0/reference/getting-started

    def query_virustotal(self, keyword="027.ru"):   # CHECK IF KEYWORD IS IP OR DOMAIN
        print(f"\n~~~~~~~~~~~~~~~ VIRUSTOTAL ~~~~~~~~~~~~~~~")
        try:
            # retrieve URL scan reports
            # https://developers.virustotal.com/v2.0/reference/url-report
            url = f"{self.virustotal_api_url}url/report?apikey={self.analyst_profile.virustotal_api_key}&resource={keyword}"
            response = requests.get(url)
            decoded_response = json.loads(response.text)
            print(json.dumps(decoded_response, indent=4))

            # retrieves a domain report
            # https://developers.virustotal.com/v2.0/reference/domain-report
            url = f"{self.virustotal_api_url}domain/report?apikey={self.analyst_profile.virustotal_api_key}&domain={keyword}"
            response = requests.get(url)
            decoded_response = json.loads(response.text)
            print(json.dumps(decoded_response, indent=4))

            # retrieve an IP address report
            # https://developers.virustotal.com/v2.0/reference/ip-address-report
            keyword = "90.156.201.97"
            url = f"{self.virustotal_api_url}ip-address/report?apikey={self.analyst_profile.virustotal_api_key}&ip={keyword}"
            response = requests.get(url)
            decoded_response = json.loads(response.text)
            print(json.dumps(decoded_response, indent=4))
        except Exception as e:
            print(f"[!] Error ocurred while quering the VirusTotal's API")
            print(e)

    # API Reference: https://shodan.readthedocs.io/en/latest/examples/basic-search.html
    # used package: https://github.com/achillean/shodan-python
    # code source : https://subscription.packtpub.com/book/networking-&-servers/9781784392932/1/ch01lvl1sec11/gathering-information-using-the-shodan-api
    def query_shodan(self, keyword="mail.elf.stuba.sk"):  # CHECK IF KEYWORD IS IP OR DOMAIN
        print(f"\n~~~~~~~~~~~~~~~ SHODAN ~~~~~~~~~~~~~~~")
        api = shodan.Shodan(self.analyst_profile.shodan_api_key)
        target = keyword
        url = f"{self.shodan_api_url}dns/resolve?hostnames={target}&key={self.analyst_profile.shodan_api_key}"
        try:
            # resolve target domain to an IP address
            response = requests.get(url)
            decoded_response = json.loads(response.text)
            # print(json.dumps(decoded_response, indent=4))
            host_ip = decoded_response[target]
            # print(f"[*] Resolved '{target}' to '{host_ip}'")

            # execute a Shodan search on the resolved IP
            result = api.host(host_ip)
            decoded_response = json.dumps(result, indent=4)
            self.output_report("shodan", decoded_response)

            print("[*] General Information")
            print(f"IP: {result['ip_str']}")
            print(f"Hostnames: {result['hostnames']}")
            print(f"Domains: {result['domains']}")
            print(f"Country: {result['country_name']}")
            print(f"City: {result['city']}")
            print(f"Organization: {result['org']}")
            print(f"ISP: {result['isp']}")
            print(f"ASN: {result['asn']}\n")
            # print(f"Operating System: {result['os']}")

            # print all banners
            print("[*] Open ports")
            print(f"{result['ports']}\n")
            # for item in result['data']:
            #     print(f"Port: {item['port']}")
            #     print(f"Banner: {item['data']}")

            # print vuln information
            if "vulns" in result:   # there may not be any vulns
                print("[*] Vulnerabilities")
                print(result['vulns'])
                # slow approach
                # for item in result['vulns']:
                # CVE = item.replace('!', '')
                # print(f"Vulns: {item}")
                # exploits = api.exploits.search(CVE)
                # for item in exploits['matches']:
                #     if item.get('cve')[0] == CVE:
                #         print(f"{item.get('description')}")

        except Exception as e:
            print(f"[!] Error ocurred while quering the Shodan's API")
            print(e)

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
                f"[~] Creating '{self.report_dir}' for storing analysis reports")
            os.mkdir(self.report_dir)

        with open(f"{self.report_dir}/{service_name}.json", "w") as output:
            output.write(json_object)


