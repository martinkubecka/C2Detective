import sys
import os
import logging
import pprint
import time
import requests
from colorama import Fore
from colorama import Back
from prettytable import PrettyTable
# https://lindevs.com/disable-tensorflow-2-debugging-information
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
from dgad.prediction import Detective


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
        self.c2_indicators_detected = False
        self.packet_parser = packet_parser
        self.enrichment_enchine = enrichment_enchine
        # self.tor_exit_nodes_list_url = "https://www.dan.me.uk/torlist/?exit"
        self.tor_nodes, self.tor_exit_nodes = self.get_tor_nodes()

    def evaluate_detection(self):
        if self.c2_indicators_detected:
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.YELLOW}Command & Control communication indicators detected{Fore.RESET}")
            logging.info(f"Command & Control communication indicators detected")
        else:
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.GREEN}Command & Control communication indicators not detected{Fore.RESET}")
            logging.info(f"Command & Control communication indicators not detected")

    def get_tor_nodes(self):
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Loading cached TOR node list ...")
        logging.info("Loading cached TOR node list")

        # NOTE: TEMPORARY SOLUTION ; WILL BE CHANGED WHEN PROPER CACHING IS IMPLMEMENTED
        filepath = f"{os.path.dirname(os.path.realpath(sys.argv[0]))}/iocs/tor"

        with open(f"{filepath}/tor_nodes_list.txt", "r") as nodes_file:
            tor_nodes = [line.rstrip() for line in nodes_file]

        with open(f"{filepath}/tor_exit_nodes_list.txt", "r") as nodes_file:
            exit_nodes = [line.rstrip() for line in nodes_file]

        return tor_nodes, exit_nodes

        # # you can only fetch the data every 30 minutes
        # response = requests.get(self.tor_exit_nodes_list_url)
        # data = response.text
        # # returns string, each IP on separate line, split on a new line character
        # nodes_list = data.split("\n")

        # return nodes_list

    def detect_outgoing_traffic_to_tor(self):
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Looking for outgoing network traffic to TOR exit nodes ...")
        logging.info("Looking for outgoing network traffic to TOR exit nodes")

        detected_ips = []
        detected = False
        for dst_ip in self.packet_parser.dst_unique_ip_list:
            if dst_ip in self.tor_exit_nodes:
                detected_ips.append(dst_ip)
                detected = True

        if detected:
            self.c2_indicators_detected = True
            print(
                f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.RED}Detected outgoing network traffic to TOR exit nodes{Fore.RESET}")
            logging.info(
                f"Detected outgoing network traffic to TOR exit nodes. (detected_ips : {detected_ips})")
            self.print_detected_tor_exit_nodes(detected_ips)
        else:
            print(
                f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.GREEN}Outgoing network traffic to TOR exit nodes not detected{Fore.RESET}")
            logging.info(
                f"Outgoing network traffic to TOR exit nodes not detected")

    def print_detected_tor_exit_nodes(self, detected_ips):
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Listing network traffic to detected TOR exit nodes")
        logging.info(f"Listing network traffic to detected TOR exit nodes")

        for src_ip, dst_ip in self.packet_parser.external_connections:
            if src_ip in detected_ips:
                print(f">> {Fore.RED}{src_ip}{Fore.RESET} -> {dst_ip}")
            if dst_ip in detected_ips:
                print(f">> {src_ip} -> {Fore.RED}{dst_ip}{Fore.RESET}")

    def detect_tor_traffic(self):
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Looking for network traffic to public TOR nodes ...")
        logging.info("Looking for network traffic to public TOR nodes")

        detected_ips = []
        detected = False
        for dst_ip in self.packet_parser.dst_unique_ip_list:
            if dst_ip in self.tor_nodes:
                detected_ips.append(dst_ip)
                detected = True

        if detected:
            self.c2_indicators_detected = True
            print(
                f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.RED}Detected network traffic to public TOR nodes{Fore.RESET}")
            logging.info(
                f"Detected network traffic to public TOR nodes. (detected_ips : {detected_ips})")
            self.print_detected_tor_nodes(detected_ips)
        else:
            print(
                f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.GREEN}Network traffic to public TOR nodes not detected{Fore.RESET}")
            logging.info(f"Network traffic to public TOR nodes not detected")

    def print_detected_tor_nodes(self, detected_ips):
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Listing traffic to public TOR nodes")
        logging.info(f"Listing traffic to public TOR nodes")

        for src_ip, dst_ip in self.packet_parser.external_connections:
            if src_ip in detected_ips:
                print(f">> {Fore.RED}{src_ip}{Fore.RESET} -> {dst_ip}")
            if dst_ip in detected_ips:
                print(f">> {src_ip} -> {Fore.RED}{dst_ip}{Fore.RESET}")

    # def detect_malicious_user_agents(self):
    #     print(
    #         f"[{time.strftime('%H:%M:%S')}] [INFO] Investigating extracted User-Agents ...")
    #     logging.info("Investigating extracted User-Agents")

    #     ua_detected = False
    #     detected_user_agents = []

    #     for connection in self.packet_parser.http_requests:
    #         # TODO: add function to extract only user_agents to its own array
    #         print(connection['user_agent'])

    #     if ua_detected:
    #         print(
    #             f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.RED}Detected known malicious User-Agents{Fore.RESET}")
    #         logging.info(
    #             f"Detected known malicious User-Agents. (detected_user_agents : {detected_user_agents})")
    #         self.print_malicious_user_agents(detected_user_agents)
    #     else:
    #         print(
    #             f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.GREEN}Known malicious User-Agents not detected{Fore.RESET}")
    #         logging.info(f"Known malicious User-Agents not detected")

    # def print_malicious_user_agents(self):
    #     print(
    #         f"[{time.strftime('%H:%M:%S')}] [INFO] Listing detected known malicious User-Agents")
    #     logging.info(f"Listing detected known malicious User-Agents")
    #     for domain in detected_domains:
    #         print(f"{Fore.RED}{domain}{Fore.RESET}")

    # DGA Detective : https://cossas-project.org/portfolio/dgad/
    # source code: https://github.com/COSSAS/dgad
    # package: https://pypi.org/project/dgad/

    def detect_dga(self):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Hunting domains generated by Domain Generation Algorithms (DGA) ...")
        logging.info(
            "Hunting domains generated by Domain Generation Algorithms (DGA)")
        dga_detected = False
        detected_domains = []

        detective = Detective()
        # convert extracted rrnames strings into dgad.schema.Domain
        mydomains, _ = detective.prepare_domains(self.packet_parser.rrnames)
        # classify them
        detective.investigate(mydomains)

        for entry in mydomains:
            report = str(entry)
            if "is_dga=True" in report:
                # Domain(raw='qjdygsnoiqaudcq.com', words=...
                raw_split = report.split("raw='")[1]
                dga_domain = raw_split.split("', words=")[0]
                dga_detected = True
                detected_domains.append(dga_domain)

        if dga_detected:
            self.c2_indicators_detected = True
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.RED}Detected domains generated by Domain Generation Algorithms (DGA){Fore.RESET}")
            logging.info(
                f"Detected domains generated by Domain Generation Algorithms (DGA). (detected_domains : {detected_domains})")
            self.print_dga_domains(detected_domains)
        else:
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.GREEN}Domains generated by Domain Generation Algorithms (DGA) not detected{Fore.RESET}")
            logging.info(
                f"Domains generated by Domain Generation Algorithms (DGA) not detected")

    def print_dga_domains(self, detected_domains):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Listing detected domains generated by Domain Generation Algorithms (DGA)")
        logging.info(
            f"Listing detected domains generated by Domain Generation Algorithms (DGA)")
        for domain in detected_domains:
            print(f">> {Fore.RED}{domain}{Fore.RESET}")

    # ----------------------------------------------------------------------------------------------------------------
    # -------------------------------------------- THREAT FEEDS DETECTION --------------------------------------------
    # ----------------------------------------------------------------------------------------------------------------

    def threat_feeds(self):
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Using threat feeds and enrichment services ...")
        logging.info("Using threat feeds and enrichment services")
        c2_ips_detected, detected_ips = self.detect_malicious_ip_addresses()
        c2_domains_detected, detected_domains = self.detect_malicious_domains()

        if c2_ips_detected:
            self.c2_indicators_detected = True
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.RED}Malicious IP addresses which received/initiated connections detected{Fore.RESET}")
            logging.info(f"Malicious IP addresses which received/initiated connections detected")
            self.print_malicious_connections(detected_ips)
        else:
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.GREEN}Malicious IP addresses which received/initiated connections not detected{Fore.RESET}")
            logging.info(f"Malicious IP addresses which received/initiated connections not detected")

        if c2_domains_detected:
            self.c2_indicators_detected = True
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.RED}Malicious domains which received/initiated connections detected{Fore.RESET}")
            logging.info(f"Malicious domains which received/initiated connections detected")
            self.print_malicious_domains(detected_domains)
        else:
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.GREEN}Malicious domains which received/initiated connections not detected{Fore.RESET}")
            logging.info(f"Malicious domains which received/initiated connections not detected")
        


    # REQUIRES threatfox or urlhaus enrichment service enabled
    # RECOMMENDED to enable both services
    def detect_malicious_ip_addresses(self):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Detecting malicious IP addresses which received/initiated connections ...")
        logging.info(
            "Detecting malicious IP addresses which received/initiated connections")

        detected_ips = []
        c2_detected = False

        for ip, count in self.packet_parser.all_ip_counter.most_common():
            # print(f"{ip} : {count}")
            enriched_ip = self.enrichment_enchine.enrich_data(
                ip)   # TODO: REWORK
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
            f"[{time.strftime('%H:%M:%S')}] [INFO] Listing external connections with C2 servers")
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
                print(f">> {Fore.RED}{src_ip}{Fore.RESET} -> {dst_ip}")
            if dst_ip in detected_ip_iocs:
                print(f">> {src_ip} -> {Fore.RED}{dst_ip}{Fore.RESET}")

    def detect_malicious_domains(self):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Detecting malicious domains which received/initiated connections ...")
        logging.info(
            "Detecting malicious domains which received/initiated connections")

        detected_domains = []
        c2_detected = False

        for domain in self.packet_parser.rrnames:
            enriched_domain = self.enrichment_enchine.enrich_data(
                domain)   # TODO: REWORK
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
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Listing detected domains for C2 servers")
        logging.info(f"Listing detected domains for C2 servers")
        for domain in detected_domains:
            print(f">> {Fore.RED}{domain}{Fore.RESET}")

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
