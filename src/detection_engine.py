from dgad.prediction import Detective
import sys
import json
import os
import logging
import pprint
import time
import requests
from colorama import Fore
from colorama import Back
from prettytable import PrettyTable
from scapy.all import *
from scapy.layers import http

# https://lindevs.com/disable-tensorflow-2-debugging-information
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'  # suppress TensorFlow logging


"""
start_time :                                timestamp when packet capture stared    string          %Y-%m-%d %H:%M:%S
end_time :                                  timestamp when packet capture ended     string          %Y-%m-%d %H:%M:%S
all_connections/external_connections :      unique connection src-dst IP pairs :    set() :         (src_ip, dst_ip)
connection_frequency :                      all TCP connections with frequencies :  {} :            {(src_ip, src_port, dst_ip, dst_port):count, ...} 
public_src_ip_list/_dst_ip_list/_ip_list :  all public source/destination IPs :     [] :            [ ip, ip, ... ] 
src_/dst_/combined_/unique_ip_list :        unique source/destination IPs :         [] :            [ ip, ip, ... ]
src_ip_/dst_ip_/all_ip_/counter :           IP quantity :                           {} :            { ip:count, ip:count, ... }
rrnames :                                   extrcted domain names from DNS :        set() :         [ domain, domain, ... ]
http_payloads :                             HTTP payloads :                         [] :            [ payload, payload, ... ]
http_sessions :                             HTTP sessions :                         [{}, {}, ...] : [ {src_ip:, src_port:, dst_ip:, dst_port:, http_payload:}, {}, ... ]  
urls :                                      extracted URLs :                        set() :         [ url, url, ... ]
http_requests :                             detailed HTTP requests                  [{}, {}, ...] : [ {src_ip:, src_port:, dst_ip:, dst_port:, method:, host:, path:, url:, user_agent:}, {}, ... ]
"""


class DetectionEngine:
    def __init__(self, analyst_profile, packet_parser, enrichment_enchine):
        self.logger = logging.getLogger(__name__)
        self.c2_indicators_detected = False

        self.analyst_profile = analyst_profile
        self.packet_parser = packet_parser
        self.enrichment_enchine = enrichment_enchine

        self.tor_nodes, self.tor_exit_nodes = self.get_tor_nodes()
        self.crypto_domains = self.get_crypto_domains()
        self.c2_http_headers = self.get_c2_http_headers()
        self.c2_tls_certificate_values = self.get_c2_tls_certificate_values()

    def evaluate_detection(self):
        if self.c2_indicators_detected:
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.YELLOW}Command & Control communication indicators detected{Fore.RESET}")
            logging.info(
                f"Command & Control communication indicators detected")
        else:
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.GREEN}Command & Control communication indicators not detected{Fore.RESET}")
            logging.info(
                f"Command & Control communication indicators not detected")

    def get_c2_http_headers(self):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Loading known C2 HTTP headers ...")
        logging.info("Loading known C2 HTTP headers")
        
        filepath = f"{os.path.dirname(os.path.realpath(sys.argv[0]))}/config/c2_http_headers.json"

        with open(filepath, 'r') as http_headers:
            c2_http_headers = json.load(http_headers)

        return c2_http_headers

    def get_tor_nodes(self):
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Loading cached TOR node list ...")
        logging.info("Loading cached TOR node list")

        filepath = f"{os.path.dirname(os.path.realpath(sys.argv[0]))}/iocs/tor/tor_nodes.json"

        with open(filepath, 'r') as tor_nodes_iocs:
            data = json.load(tor_nodes_iocs)
            tor_nodes = data['all_nodes']
            exit_nodes = data['exit_nodes']

        return tor_nodes, exit_nodes

    def get_crypto_domains(self):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Loading cached crypto / cryptojacking based sites list ...")
        logging.info("Loading cached crypto / cryptojacking based sites list")

        filepath = f"{os.path.dirname(os.path.realpath(sys.argv[0]))}/iocs/crypto_domains/crypto_domains.json"

        with open(filepath, 'r') as crypto_domains_iocs:
            data = json.load(crypto_domains_iocs)
            crypto_domains = data['crypto_domains']

        return crypto_domains

    def get_c2_tls_certificate_values(self):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Loading known C2 values in TLS certificates ...")
        logging.info("Loading known C2 values in TLS certificates")
        
        filepath = f"{os.path.dirname(os.path.realpath(sys.argv[0]))}/config/c2_tls_certificate_values.json"

        with open(filepath, 'r') as tls_values:
            c2_tls_certificate_values = json.load(tls_values)

        return c2_tls_certificate_values

    # ----------------------------------------------------------------------------------------------------------------
    # ------------------------------------------- NETWORK TRAFFIC DETECTION ------------------------------------------
    # ----------------------------------------------------------------------------------------------------------------

    def detect_connections_with_excessive_frequency(self):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Looking for connections with excessive frequency ...")
        logging.info("Looking for connections with excessive frequency")

        MAX_FREQUENCY = len(self.packet_parser.packets) * (self.analyst_profile.MAX_FREQUENCY / 100)

        detected = False
        detected_connections = {}

        # find connections with excessive frequency
        for connection, count in self.packet_parser.connection_frequency.items():
            if count > MAX_FREQUENCY:
                detected = True
                detected_connections[connection] = count
                # print(f"Connection {connection} has {count} packets, which is over {threshold:.0f}% of total packets.")

        if detected:
            self.c2_indicators_detected = True
            print(
                f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.RED}Detected connections with excessive frequency{Fore.RESET}")
            logging.info(
                f"Detected connections with excessive frequency. (detected_connections : {detected_connections})")
            self.print_detected_connections_with_excessive_frequency(detected_connections)
        else:
            print(
                f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.GREEN}Connections with excessive frequency not detected{Fore.RESET}")
            logging.info(f"Connections with excessive frequency not detected")

    def print_detected_connections_with_excessive_frequency(self, detected_connections):
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Listing connections with excessive frequency")
        logging.info(f"Listing connections with excessive frequency")

        for connection, count in detected_connections.items():
            src_ip = connection[0]
            src_port = connection[1]
            dst_ip = connection[2]
            dst_port = connection[3]
            print(f">> {Fore.RED}{src_ip}:{src_port} -> {dst_ip}:{dst_port}{Fore.RESET} = {count}/{len(self.packet_parser.packets)} connections")

    def detect_long_connection(self):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Looking for connections with long duration ...")
        logging.info("Looking for connections with long duration")

        detected = False
        MAX_DURATION = self.analyst_profile.MAX_DURATION    # 14000 set for testing 'Qakbot.pcap'
        connection_start_times = {}
        detected_connections = []

        for packet in self.packet_parser.packets:
            # check if packet has IP and TCP layers
            if IP in packet and TCP in packet:
                # extract connection information
                src_ip = packet[IP].src
                src_port = packet[TCP].sport
                dst_ip = packet[IP].dst
                dst_port = packet[TCP].dport
                connection = (src_ip, src_port, dst_ip, dst_port)

                # check if connection is in dictionary
                if connection not in connection_start_times:
                    # add connection to dictionary with current time as start time
                    connection_start_times[connection] = packet.time
                else:
                    # calculate time duration of connection
                    duration = packet.time - connection_start_times[connection]

                    # check if duration exceeds maximum set duration
                    if duration > MAX_DURATION:
                        detected = True
                        detected_connections.append((src_ip, src_port, dst_ip, dst_port, duration))

        if detected:
            unqiue_detected = set((str(connection) for connection in detected_connections))
            count_unqiue_detected = len(unqiue_detected)
            self.c2_indicators_detected = True
            print(
                f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.RED}Detected {count_unqiue_detected} connections with long duration{Fore.RESET}")
            logging.info(
                f"Detected {count_unqiue_detected} connections with long duration. (detected_connections : {unqiue_detected})")
            # TODO : process / display which connections (src IP - dst IP) were detected
        else:
            print(
                f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.GREEN}Connections with long duration not detected{Fore.RESET}")
            logging.info(f"Connections with long duration not detected")

    def detect_big_HTML_response_size(self):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Looking for unusual big HTML response size ...")
        logging.info("Looking for unusual big HTML response size")

        detected = False
        MAX_HTML_SIZE = self.analyst_profile.MAX_HTML_SIZE

        connection_sizes = {}

        for packet in self.packet_parser.packets:
            # check if packet contains HTTP responses
            if packet.haslayer(http.HTTPResponse):
                response = packet.getlayer(http.HTTPResponse)
                
                # if packet has respone and Content Length, check if it is larger than the threshold
                if response and response.Content_Length and int(response.Content_Length) > MAX_HTML_SIZE:
                    detected = True
                    connection = (packet[IP].src, packet[TCP].sport, packet[IP].dst, packet[TCP].dport)
                    
                    if connection not in connection_sizes:
                        connection_sizes[connection] = 0
                    
                    connection_sizes[connection] += int(response.Content_Length)

        if detected:
            self.c2_indicators_detected = True
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.RED}Detected unusual big HTML response size{Fore.RESET}")
            logging.info(f"Detected unusual big HTML response size")
            self.print_connections_with_big_HTML_response_size(connection_sizes, MAX_HTML_SIZE)
        else:
            print(
                f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.GREEN}Unusual big HTML response size not detected{Fore.RESET}")
            logging.info(f"Unusual big HTML response size not detected")

    def print_connections_with_big_HTML_response_size(self, connection_sizes, MAX_HTML_SIZE):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Listing connections with unusual big HTML response size")
        logging.info(f"Listing connections with unusual big HTML response size")

        for connection, size in connection_sizes.items():
            if size > MAX_HTML_SIZE:
                src_ip = connection[0]
                src_port = connection[1]
                dst_ip = connection[2]
                dst_port = connection[3]
                print(f">> {Fore.RED}{src_ip}:{src_port} -> {dst_ip}:{dst_port}{Fore.RESET} = {size} bytes")

    def detect_known_malicious_HTTP_headers(self):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Looking for known malicious HTTP headers ...")
        logging.info("Looking for known malicious HTTP headers")

        detected = False
        detected_headers = []

        for entry in self.packet_parser.http_sessions:
            for key, value in entry['http_headers'].items():
                for c2_framework, http_headers in self.c2_http_headers.items():
                    for malicious_header in http_headers:
                        if malicious_header in value:
                            detected = True
                            entry = dict(
                                c2_framework=c2_framework,
                                malicious_header=malicious_header,
                                session=entry
                            )
                            detected_headers.append(entry)

        if detected:
            self.c2_indicators_detected = True
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.RED}Detected known malicious HTTP headers{Fore.RESET}")
            logging.info(f"Detected known malicious HTTP headers. (detected_headers : {detected_headers})")
            self.print_detected_malicious_headers(detected_headers)
        else:
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.GREEN}Known malicious HTTP headers not detected{Fore.RESET}")
            logging.info(f"Known malicious HTTP headers not detected")

    def print_detected_malicious_headers(self, detected_headers):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Listing detected HTTP sessions which contain known malicious HTTP headers")
        logging.info(f"Listing detected HTTP sessions which contain known malicious HTTP headers")
   
        for entry in detected_headers:
            print(f">> {Fore.RED}'{entry['c2_framework']}' : '{entry['malicious_header']}'{Fore.RESET} in '{entry['session']}'")

    def detect_known_c2_tls_values(self):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Looking for known malicious values in extracted data from TLS certificates ...")
        logging.info("Looking for known malicious values in extracted data from TLS certificates")

        detected_certificates = []

        for entry in self.packet_parser.certificates:          

            for c2_framework, tls_values in self.c2_tls_certificate_values.items():
                detected_value = False

                for malicious_value in tls_values:

                    if malicious_value in entry.get('serialNumber'):
                        detected_value = True

                    if malicious_value in entry.get('issuer').values():
                        detected_value = True

                    if malicious_value in entry.get('subject').values():
                        detected_value = True

            if detected_value:
                detected_certificates.append(entry)

        if detected_certificates:
            self.c2_indicators_detected = True
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.RED}Detected known malicious values in extracted data from TLS certificates{Fore.RESET}")
            logging.info(f"Detected known malicious values in extracted data from TLS certificates. (detected_certificates : {detected_certificates})")
            self.print_detected_malicious_certificates(detected_certificates)
        else:
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.GREEN}Known malicious values in extracted data from TLS certificates not detected{Fore.RESET}")
            logging.info(f"Known malicious values in extracted data from TLS certificates not detected")

    def print_detected_malicious_certificates(self, detected_certificates):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Listing detected malicious TLS certificates")
        logging.info(f"Listing detected malicious TLS certificates")
   
        for entry in detected_certificates:
            print(f"{Fore.RED}{entry}{Fore.RESET}")

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
            logging.info(
                f"Malicious IP addresses which received/initiated connections detected")
            self.print_malicious_connections(detected_ips)
        else:
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.GREEN}Malicious IP addresses which received/initiated connections not detected{Fore.RESET}")
            logging.info(
                f"Malicious IP addresses which received/initiated connections not detected")

        if c2_domains_detected:
            self.c2_indicators_detected = True
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.RED}Malicious domains which received/initiated connections detected{Fore.RESET}")
            logging.info(
                f"Malicious domains which received/initiated connections detected")
            self.print_malicious_domains(detected_domains)
        else:
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.GREEN}Malicious domains which received/initiated connections not detected{Fore.RESET}")
            logging.info(
                f"Malicious domains which received/initiated connections not detected")

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

    def detect_crypto_domains(self):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Looking for network traffic to crypto / cryptojacking based sites ...")
        logging.info(f"Looking for network traffic to crypto / cryptojacking based sites")

        detected = False
        detected_domains = []

        for domain in self.packet_parser.rrnames:
            if domain in self.crypto_domains:
                detected = True
                detected_domains.append(domain)

        if detected:
            self.c2_indicators_detected = True
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.RED}Detected crypto / cryptojacking based sites{Fore.RESET}")
            logging.info(f"Detected crypto / cryptojacking based sites (detected_domains : {detected_domains})")
            self.print_crypto_domains(detected_domains)
        else:
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.GREEN}Crypto / cryptojacking based sites not detected{Fore.RESET}")
            logging.info(f"Crypto / cryptojacking based sites not detected")

    def print_crypto_domains(self, detected_domains):
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Listing detected crypto / cryptojacking based sites")
        logging.info(f"Listing detected crypto / cryptojacking based sites")
        for domain in detected_domains:
            print(f">> {Fore.RED}{domain}{Fore.RESET}")