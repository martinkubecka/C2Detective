import logging
import pprint
import time
from colorama import Fore
from colorama import Back
from prettytable import PrettyTable

# detect malicious domains which received connections
# detect malicious domains which initiated connections


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

    def threat_feeds(self):
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Using selected threat feeds and enrichment services ...")
        logging.info("Using selected Threat Feeds and enrichment services")
        c2_detected = False
        c2_detected, detected_ips = self.detect_malicious_ip_addresses()
        c2_detected, detected_domains = self.detect_malicious_domains()

        if c2_detected:
            print(
                f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.RED}Command & Control communication detected{Fore.RESET}")
            logging.info(f"Command & Control communication detected. (detected_ips : {detected_ips}) ; (detected_domains : {detected_domains})")
            
            if detected_ips:
                self.print_malicious_connections(detected_ips)

            if detected_domains:
                self.print_malicious_domains(detected_domains)

        else: # may lead to FALSE NEGATIVE results ::: only for TESTING
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.GREEN}Command & Control communication was not detected{Fore.RESET}")
            logging.info(f"Command & Control communication was not detected")

    # REQUIRES threatfox or urlhaus enrichment service enabled
    # RECOMMENDED to enable both services
    def detect_malicious_ip_addresses(self):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Detecting malicious IP addresses which received/initiated connections ...")
        logging.info("Detecting malicious IP addresses which received/initiated connections")

        detected_ips = []
        c2_detected = False

        for ip, count in self.packet_parser.all_ip_counter.most_common():
            # print(f"{ip} : {count}")
            enriched_ip = self.enrichment_enchine.enrich_data(ip)   # TODO: REWORK 
            # maybe call specific service directly ...                      <------
            # only 'threatfox' and 'urlhaus' are useful

            if enriched_ip:  # target has some record

                threatfox = enriched_ip.get('threatfox')
                urlhaus = enriched_ip.get('urlhaus')

                if threatfox:
                    # ['threatfox']['threat_type'] == "botnet_cc"
                    threatfox_threat_type = threatfox.get('threat_type')
                    if threatfox_threat_type:
                        if threatfox_threat_type == "botnet_cc":
                            c2_detected = True
                            # print(f"{ip} : botnet_cc")
                            # maybe append the whole threatfox entry for additional data
                            detected_ips.append(ip)

                if urlhaus:
                    # ['urlhaus']['urls'][0]['threat'] == "malware_download"
                    urlhaus_urls = urlhaus.get('urls')
                    if urlhaus_urls:
                        for url in urlhaus_urls:
                            threat = url.get('threat')
                            if threat == "malware_download":
                                c2_detected = True
                                # print(f"{ip} : malware_download")
                                detected_ips.append(ip)
        
        return c2_detected, detected_ips
        
    def print_malicious_connections(self, detected_ip_iocs):
        print(
            f"\n[{time.strftime('%H:%M:%S')}] [INFO] Listing external connections with C2 servers\n")
        logging.info(f"Listing external connections with C2 servers")
        # table = PrettyTable(["Source IP", "Destination IP"])     
        # for src_ip, dst_ip in self.packet_parser.external_connections:
        #     if src_ip in detected_ip_iocs:
        #         table.add_row([src_ip, dst_ip])
        #     if dst_ip in detected_ip_iocs:
        #         table.add_row([src_ip, dst_ip])
        # print(table)

        for src_ip, dst_ip in self.packet_parser.external_connections:
            if src_ip in detected_ip_iocs:
                print(f"{Fore.RED}{src_ip}{Fore.RESET} -> {dst_ip}")
            if dst_ip in detected_ip_iocs:
                print(f"{src_ip} -> {Fore.RED}{dst_ip}{Fore.RESET}")


    def detect_malicious_domains(self):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Detecting malicious domains which received/initiated connections ...")
        logging.info("Detecting malicious domains which received/initiated connections")

        detected_domains = []
        c2_detected = False

        for domain in self.packet_parser.rrnames:
            enriched_domain = self.enrichment_enchine.enrich_data(domain)   # TODO: REWORK 
            # maybe call specific service directly ...                      <------
            # only 'threatfox' and 'urlhaus' are useful

            if enriched_domain:  # target has some record

                threatfox = enriched_domain.get('threatfox')
                urlhaus = enriched_domain.get('urlhaus')

                if threatfox:
                    # ['threatfox']['threat_type'] == "botnet_cc"
                    threatfox_threat_type = threatfox.get('threat_type')
                    if threatfox_threat_type:
                        if threatfox_threat_type == "botnet_cc":
                            c2_detected = True
                            # print(f"{domain} : botnet_cc")
                            # maybe append the whole threatfox entry for additional data
                            detected_domains.append(domain)

                if urlhaus:
                    # ['urlhaus']['urls'][0]['threat'] == "malware_download"
                    urlhaus_urls = urlhaus.get('urls')
                    if urlhaus_urls:
                        for url in urlhaus_urls:
                            threat = url.get('threat')
                            if threat == "malware_download":
                                c2_detected = True
                                # print(f"{domain} : malware_download")
                                detected_domains.append(domain)

        return c2_detected, detected_domains

    def print_malicious_domains(self, detected_domains):
        print(f"\n[{time.strftime('%H:%M:%S')}] [INFO] Listing detected domains for C2 servers\n")
        logging.info(f"Listing detected domains for C2 servers")
        for domain in detected_domains:
            print(f"{Fore.RED}{domain}{Fore.RESET}") 

    # def threatfox_analysis(self, enriched_ip):
    #     threatfox = enriched_ip.get('threatfox')
    #     if threatfox:
    #         ioc = threatfox.get('ioc')
    #         threat_type = threatfox.get('threat_type')
    #         malware = threatfox.get('malware')
    #         confidence_level = threatfox.get('confidence_level')
    #         first_seen = threatfox.get('first_seen')
    #         last_seen = threatfox.get('last_seen')
    #         # print(f"{ioc} : {threat_type} : {malware} : {confidence_level} : {first_seen} : {last_seen}")
    #         entry = dict(
    #             ioc=ioc,
    #             threat_type=threat_type,
    #             malware=malware,
    #             confidence_level=confidence_level,
    #             first_seen=first_seen,
    #             last_seen=last_seen
    #         )
    #     return
