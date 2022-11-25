import logging

# detect malicious domains which received connections
# detect malicious domains which initiated connections
# detect malicious IPs which received connections
# detect malicious IPs which initiated connections

"""
all_connections/external_connections :      unique connection src-dst IP pairs :    set() :         (src_ip, dst_ip)
src_ip_list/dst_ip_list/ip_list :           all public source/destination IPs :     [] :            [ ip, ip, ... ] 
src_/dst_/combined_/unique_ip_list :        unique source/destination IPs :         [] :            [ ip, ip, ... ]
src_ip_/dst_ip_/all_ip_/counter :           IP quantity :                           {} :            { ip:count, ip:count, ... }
rrnames :                                   extrcted domain names from DNS :        set() :         [ domain, domain, ... ]
http_payloads :                             HTTP payloads :                         [] :            [ payload, payload, ... ]
http_sessions :                             HTTP sessions :                         [{}, {}, ...] : [ {src_ip:, src_port:, dst_ip:, dst_port:, http_payload:}, {}, ... ]  
urls :                                      extracted URLs :                        set() :         [ url, url, ... ]
http_requests :                             detailed HTTP requests                  [{}, {}, ...] : [ {src_ip:, src_port:, dst_ip:, dst_port:, method:, host:, path:, url:, user_agent:}, {}, ... ]
"""

class DetectionEngine:
    def __init__(self, packet_parser, enrichment_enchine):
        self.logger = logging.getLogger(__name__)
        self.packet_parser = packet_parser
        self.enrichment_enchine = enrichment_enchine

    def detect_connections(self):

        for ip, count in self.packet_parser.all_ip_counter.most_common():
            # print(f"{ip} : {count}")
            enriched_ip = self.enrichment_enchine.enrich_data(ip)
            # print(enriched_ip)

        return