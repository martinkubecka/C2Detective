import requests
import json


class Enrichment:
    def __init__(self, analyst_profile, packet_parser):
        self.analysis_profile = analyst_profile
        self.packet_parser = packet_parser
        self.abuseipdb_api_url = 'https://api.abuseipdb.com/api/v2/check'

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
            decodedResponse = json.loads(response.text)
            print(json.dumps(decodedResponse, sort_keys=True, indent=4))
