import requests
import json


class Enrichment:
    def __init__(self, analyst_profile, packet_parser):
        self.analysis_profile = analyst_profile
        self.packet_parser = packet_parser
        self.abuseipdb_api_url = 'https://api.abuseipdb.com/api/v2/check'
        self.securitytrails_api_url = "https://api.securitytrails.com/v1/"
        self.shodan_api_key = self.analysis_profile.shodan_api_key
        self.censys_api_key = self.analysis_profile.censys_api_key
        self.censys_secret = self.analysis_profile.censys_secret

    # CHECK Endpoint : https://docs.abuseipdb.com/#check-endpoint
    def query_abuseipdb(self, ip_list):

        for ip in ip_list:
            querystring = {
                'ipAddress': ip,
                'maxAgeInDays': '90'
            }

            headers = {
                'Accept': 'application/json',
                'Key': self.analysis_profile.abuseipdb_api_key,
                'verbose': ''
            }

            response = requests.request(
                method='GET', url=self.abuseipdb_api_url, headers=headers, params=querystring)

            # maybe throw away those with abuseConfidenceScore == 0
            decoded_response = json.loads(response.text)
            print(json.dumps(decoded_response, sort_keys=True, indent=4))

    # API Reference : https://docs.securitytrails.com/reference/ping
    # https://docs.securitytrails.com/docs
    def query_securitytrails(self, keyword="securitytrails.com"):

        headers = {"accept": "application/json",
                   'APIKEY': self.analysis_profile.securitytrails_api_key}

        # check API access
        url = self.securitytrails_api_url + "ping"
        response = requests.get(url, headers=headers)
        decoded_response = json.loads(response.text)

        if "message" in decoded_response:
            print(f"[!] {decoded_response['message']}")
            return

        # get details for current_dns: a, aaaa, mx, ns, soa, txt
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

    # https://github.com/VirusTotal/vt-py

    def query_virustotal(self):
        print()

    def query_shodan(self):
        print()

    def query_censys(self):
        print()
