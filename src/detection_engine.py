import sys
import json
import os
import logging
import pprint
import time
import sqlite3
import requests
from colorama import Fore
from colorama import Back
from prettytable import PrettyTable
from scapy.all import *
from scapy.layers import http
import tldextract
from ipaddress import ip_address
import itertools
import re

"""
start_time :                                timestamp when packet capture stared    string          %Y-%m-%d %H:%M:%S
end_time :                                  timestamp when packet capture ended     string          %Y-%m-%d %H:%M:%S
all_connections/external_connections :      unique connection src-dst IP pairs :    set() :         ((src_ip, dst_ip), ...)
connection_frequency :                      all TCP connections with frequencies :  {} :            {(src_ip, src_port, dst_ip, dst_port):count, ...} 
public_src_ip_list/_dst_ip_list/_ip_list :  all public source/destination IPs :     [] :            [ ip, ip, ... ] 
src_/dst_/combined_/unique_ip_list :        unique source/destination IPs :         [] :            [ ip, ip, ... ]
src_ip_/dst_ip_/all_ip_/counter :           IP quantity :                           {} :            { ip:count, ip:count, ... }
dns_packets :                               extracted packets with DNS layer :      [] :            [packet, packet, ...]
domain_names :                              extrcted domain names from DNS :        set() :         [ domain, domain, ... ]
http_payloads :                             HTTP payloads :                         [] :            [ payload, payload, ... ]
http_sessions :                             HTTP sessions :                         [{}, {}, ...] : [ {src_ip:, src_port:, dst_ip:, dst_port:, http_payload:}, {}, ... ]  
unique_urls :                               extracted URLs :                        set() :         [ url, url, ... ]
http_requests :                             detailed HTTP requests                  [{}, {}, ...] : [ {src_ip:, src_port:, dst_ip:, dst_port:, method:, host:, path:, url:, user_agent:}, {}, ... ]
"""


class DetectionEngine:
    def __init__(self, analyst_profile, packet_parser, enrichment_enchine):
        self.logger = logging.getLogger(__name__)
        self.c2_indicators_detected = False
        self.detected_iocs = {}

        self.analyst_profile = analyst_profile
        self.packet_parser = packet_parser
        self.enrichment_enchine = enrichment_enchine

        self.whitelisted_domains = self.get_domain_whitelist()
        self.tor_nodes, self.tor_exit_nodes = self.get_tor_nodes()
        self.crypto_domains = self.get_crypto_domains()
        self.c2_http_headers = self.get_c2_http_headers()
        self.c2_tls_certificate_values = self.get_c2_tls_certificate_values()

        self.detected_iocs['filepath'] =  self.packet_parser.get_filepath()

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

    def get_domain_whitelist(self):
        filepath = f"{os.path.dirname(os.path.realpath(sys.argv[0]))}/config/domain_whitelist.txt"
        whitelisted_domains = []

        if os.path.isfile(filepath):
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] Loading whitelisted domains ...")
            logging.info("Loading whitelisted domains")

            with open(filepath, "r") as whitelist:
                whitelisted_domains = whitelist.read().splitlines()

        return whitelisted_domains

    # ----------------------------------------------------------------------------------------------------------------
    # ------------------------------------------- NETWORK TRAFFIC DETECTION ------------------------------------------
    # ----------------------------------------------------------------------------------------------------------------

    def detect_connections_with_excessive_frequency(self):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Looking for connections with excessive frequency ...")
        logging.info("Looking for connections with excessive frequency")

        MAX_FREQUENCY = len(self.packet_parser.packets) * (self.analyst_profile.MAX_FREQUENCY / 100)

        detected = False
        detected_connections = []

        # find connections with excessive frequency
        for connection, count in self.packet_parser.connection_frequency.items():
            if count > MAX_FREQUENCY:
                detected = True
                entry = dict(
                    src_ip=connection[0],
                    src_port=connection[1],
                    dst_ip=connection[2],
                    dst_port=connection[3],
                    frequency=count
                )
                # print(f"Connection {connection} has {count} packets, which is over {threshold:.0f}% of total packets.")
                detected_connections.append(entry)

        if detected:
            self.c2_indicators_detected = True
            self.detected_iocs['excessive_frequency'] = detected_connections
            print(
                f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.RED}Detected connections with excessive frequency{Fore.RESET}")
            logging.info(
                f"Detected connections with excessive frequency. (detected_connections : {detected_connections})")
            self.print_connections_with_excessive_frequency(detected_connections)
        else:
            print(
                f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.GREEN}Connections with excessive frequency not detected{Fore.RESET}")
            logging.info(f"Connections with excessive frequency not detected")

    def print_connections_with_excessive_frequency(self, detected_connections):
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Listing connections with excessive frequency")
        logging.info(f"Listing connections with excessive frequency")

        for entry in detected_connections:
            print(f">> {Fore.RED}{entry['src_ip']}:{entry['src_port']} -> {entry['dst_ip']}:{entry['dst_port']}{Fore.RESET} = {entry['frequency']}/{len(self.packet_parser.packets)} connections")

    def detect_long_connection(self):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Looking for connections with long duration ...")
        logging.info("Looking for connections with long duration")

        detected = False
        MAX_DURATION = self.analyst_profile.MAX_DURATION    # 14000 set for testing 'Qakbot.pcap'
        
        detected_connections = []

        for connection in self.packet_parser.connections:

            if 'TCP' in connection:

                connection_arr = connection.split(" ")
                src_ip, src_port = connection_arr[1].split(":")
                dst_ip, dst_port = connection_arr[3].split(":")

                # if src or dst ip is public, further process this connection
                if not ip_address(src_ip).is_private or not ip_address(dst_ip).is_private:

                    packets = self.packet_parser.connections[connection]
                    first_packet = packets[0]
                    last_packet = packets[-1]
                    duration = last_packet.time - first_packet.time

                    if duration > MAX_DURATION:
                        detected = True
                        entry = dict(
                            src_ip=src_ip,
                            src_port=src_port,
                            dst_ip=dst_ip,
                            dst_port=dst_port,
                            duration=float(duration)
                        )
                        detected_connections.append(entry)
                else:
                    continue

        if detected:
            self.c2_indicators_detected = True
            self.detected_iocs['long_connection'] = detected_connections
            count_detected = len(detected_connections)
            print(
                f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.RED}Detected {count_detected} connections with long duration{Fore.RESET}")
            logging.info(
                f"Detected {count_detected} connections with long duration. (detected_connections : {detected_connections})")
            self.print_long_connections(detected_connections)
        else:
            print(
                f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.GREEN}Connections with long duration not detected{Fore.RESET}")
            logging.info(f"Connections with long duration not detected")

    def print_long_connections(self, detected_connections):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Listing detected connections with long duration")
        logging.info(f"Listing detected connections with long duration")

        for entry in detected_connections:
            print(f">> {Fore.RED}{entry['src_ip']}:{entry['src_port']} -> {entry['dst_ip']}:{entry['dst_port']}{Fore.RESET} = {entry['duration']} seconds")

    def detect_big_HTML_response_size(self):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Looking for unusual big HTML response size ...")
        logging.info("Looking for unusual big HTML response size")

        detected = False
        MAX_HTML_SIZE = self.analyst_profile.MAX_HTML_SIZE

        connection_sizes = []

        for packet in self.packet_parser.packets:
            # check if packet contains HTTP responses
            if packet.haslayer(http.HTTPResponse):
                response = packet.getlayer(http.HTTPResponse)
                
                # if packet has respone and Content Length, check if it is larger than the threshold
                if response and response.Content_Length and int(response.Content_Length) > MAX_HTML_SIZE:
                    detected = True
                    connection = (packet[IP].src, packet[TCP].sport, packet[IP].dst, packet[TCP].dport)
                    
                    # check if connection is already in list of dictionaries
                    index = None
                    for i, conn in enumerate(connection_sizes):
                        if connection == (conn['src_ip'], conn['src_port'], conn['dst_ip'], conn['dst_port']):
                            index = i
                            break
                            
                    # if connection is already in list of dictionaries, update the size
                    if index is not None:
                        connection_sizes[index]['size'] += int(response.Content_Length)
                    # otherwise, add a new dictionary to the list
                    else:
                        connection_sizes.append({
                            'src_ip': packet[IP].src,
                            'src_port': packet[TCP].sport,
                            'dst_ip': packet[IP].dst,
                            'dst_port': packet[TCP].dport,
                            'respone_size': int(response.Content_Length)
                        })

        if detected:
            self.c2_indicators_detected = True
            self.detected_iocs['big_HTML_response_size'] = connection_sizes
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

        for entry in connection_sizes:
            print(f">> {Fore.RED}{entry['src_ip']}:{entry['src_port']} -> {entry['dst_ip']}:{entry['dst_port']}{Fore.RESET} = {entry['respone_size']} bytes")

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
            self.detected_iocs['malicious_HTTP_headers'] = detected_headers
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.RED}Detected known malicious HTTP headers{Fore.RESET}")
            logging.info(f"Detected known malicious HTTP headers. (detected_headers : {detected_headers})")
            self.print_malicious_HTTP_headers(detected_headers)
        else:
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.GREEN}Known malicious HTTP headers not detected{Fore.RESET}")
            logging.info(f"Known malicious HTTP headers not detected")

    def print_malicious_HTTP_headers(self, detected_headers):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Listing detected HTTP sessions which contain known malicious HTTP headers")
        logging.info(f"Listing detected HTTP sessions which contain known malicious HTTP headers")
   
        for entry in detected_headers:
            print(f">> {Fore.RED}'{entry['c2_framework']}' : '{entry['malicious_header']}'{Fore.RESET} in '{entry['session']}'")

    def detect_known_c2_tls_values(self):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Looking for known malicious values in extracted data from TLS certificates ...")
        logging.info("Looking for known malicious values in extracted data from TLS certificates")

        detected_certificates = []

        for entry in self.packet_parser.certificates:          

            issuer_values = entry.get("issuer").values()
            subject_values = entry.get("subject").values()

            for c2_framework, malicious_tls_values in self.c2_tls_certificate_values.items():
                detected_value = False

                for malicious_value in malicious_tls_values:

                    if malicious_value in entry.get('serialNumber'):
                        detected_value = True

                    for value in issuer_values:
                        if malicious_value in value:
                            detected_value = True

                    for value in subject_values:
                        if malicious_value in value:
                            detected_value = True

            if detected_value:
                detected_certificates.append(entry)

        if detected_certificates:
            self.c2_indicators_detected = True
            self.detected_iocs['malicious_TLS_certificates'] = detected_certificates
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.RED}Detected known malicious values in extracted data from TLS certificates{Fore.RESET}")
            logging.info(f"Detected known malicious values in extracted data from TLS certificates. (detected_certificates : {detected_certificates})")
            self.print_known_c2_tls_certificates(detected_certificates)
        else:
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.GREEN}Known malicious values in extracted data from TLS certificates not detected{Fore.RESET}")
            logging.info(f"Known malicious values in extracted data from TLS certificates not detected")

    def print_known_c2_tls_certificates(self, detected_certificates):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Listing detected malicious TLS certificates")
        logging.info(f"Listing detected malicious TLS certificates")
   
        for entry in detected_certificates:
            print(f"{Fore.RED}{entry}{Fore.RESET}")

    def detect_outgoing_traffic_to_tor(self):
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Looking for outgoing network traffic to TOR exit nodes ...")
        logging.info("Looking for outgoing network traffic to TOR exit nodes")

        detected = False
        detected_ips = []
        seen_ips = set()

        for src_ip, dst_ip in self.packet_parser.external_connections:
            if src_ip in self.tor_exit_nodes or dst_ip in self.tor_exit_nodes:
                entry = dict(
                    src_ip=src_ip,
                    dst_ip=dst_ip
                )
                entry_frozenset = frozenset(entry.items())
                if entry_frozenset not in seen_ips:
                    detected_ips.append(entry)
                    seen_ips.add(entry_frozenset)
                    detected = True

        if detected:
            self.c2_indicators_detected = True
            self.detected_iocs['outgoing_Tor_network_traffic'] = detected_ips
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

        detected = False
        detected_ips = []
        seen_ips = set()

        for src_ip, dst_ip in self.packet_parser.external_connections:
            if src_ip in self.tor_nodes or dst_ip in self.tor_nodes:
                entry = dict(
                    src_ip=src_ip,
                    dst_ip=dst_ip
                )
                entry_frozenset = frozenset(entry.items())
                if entry_frozenset not in seen_ips:
                    detected_ips.append(entry)
                    seen_ips.add(entry_frozenset)
                    detected = True

        if detected:
            self.c2_indicators_detected = True
            self.detected_iocs['Tor_network_traffic'] = detected_ips
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
        # https://lindevs.com/disable-tensorflow-2-debugging-information
        os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'  # suppress TensorFlow logging
        from dgad.prediction import Detective 
        
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Hunting domains generated by Domain Generation Algorithms (DGA) ...")
        logging.info(
            "Hunting domains generated by Domain Generation Algorithms (DGA)")
        dga_detected = False
        detected_domains = []

        detective = Detective()
        # convert extracted domain names strings into dgad.schema.Domain
        mydomains, _ = detective.prepare_domains(self.packet_parser.domain_names)
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
            self.detected_iocs['DGA_domains'] = detected_domains
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

    def detect_dns_tunneling(self):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Looking for indicators of DNS Tunneling technique ...")
        logging.info("Looking for indicators of DNS Tunneling technique")
        
        detected = False
        detected_queries = {}

        # TODO : ADD DETECTION BASED ON THE DNS FREQUENCY

        MAX_SUBDOMAIN_LENGTH = self.analyst_profile.MAX_SUBDOMAIN_LENGTH

        for packet in self.packet_parser.dns_packets:
            if packet.haslayer(DNSQR):  # pkt.qr == 0 ; DNS query
                query = packet[DNSQR].qname.decode('utf-8')
                subdomain, domain, suffix = tldextract.extract(query)

                if "arpa" in suffix:    # provides namespaces for reverse DNS lookups
                    continue
                
                if self.whitelisted_domains:   # user defined list whitelited domains
                    detected_whitelisted_domain = False    
                    for w_domain in self.whitelisted_domains:
                        _, w_domain_name, _ = tldextract.extract(w_domain)
                        if domain == w_domain_name:
                            # continue the outermost for loop
                            detected_whitelisted_domain = True

                if detected_whitelisted_domain:
                    continue

                if len(subdomain) > MAX_SUBDOMAIN_LENGTH:    # check for long domain names
                    detected = True
                    domain = f"{domain}.{suffix}"   # build domain with TLD

                    if domain in detected_queries:
                        queries = detected_queries[domain]['queries']
                        found = False
                        
                        for entry in queries:
                            if query in entry:
                                entry[query] += 1
                                found = True
                                break
                        
                        if not found:
                            queries.append({query: 1})
                     
                        detected_queries[domain]['frequency'] += 1
                    
                    else:
                        detected_queries[domain] = {'queries': [{query: 1}], 'frequency': 1}

        if detected:
            self.c2_indicators_detected = True
            self.detected_iocs['DNS_Tunneling'] = detected_queries
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.RED}Detected DNS Tunneling technique{Fore.RESET}")
            logging.info(f"Detected DNS Tunneling technique. (detected_queries : {detected_queries})")
            self.print_dns_tunneling_indicators(detected_queries)
        else:
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.GREEN}DNS Tunneling technique not detected{Fore.RESET}")
            logging.info(f"DNS Tunneling technique not detected")

    def print_dns_tunneling_indicators(self, detected_queries):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Listing information about detected DNS Tunneling technique")
        logging.info(f"Listing information about detected DNS Tunneling technique")

        for domain, values in detected_queries.items():
            print(f">> Domain '{Fore.RED}{domain}{Fore.RESET}' queried '{values['frequency']}' times")
            print(f">>>> DNS query example with frequency: '{Fore.RED}{values['queries'][0]}{Fore.RESET}'")

    # ----------------------------------------------------------------------------------------------------------------
    # -------------------------------------------- C2Hunter Plugin --------------------------------------------
    # ----------------------------------------------------------------------------------------------------------------

    # C2Hunter threat feed collection
    # Feodo Tracker - IP addresses
    # ThreatFox - IP addresses, IP:Port, URL, Domain
    # Urlhaus - URLs which may contain IP address

    def threat_feeds(self, c2hunter_db):

        c2_ips_detected, detected_ips = self.detect_c2_ip_addresses(c2hunter_db)
        
        if c2_ips_detected:
            self.c2_indicators_detected = True
            self.detected_iocs['c2_ip_address'] = detected_ips
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.RED}C2 IP addresses which received/initiated connections detected{Fore.RESET}")
            logging.info(f"C2 IP addresses which received/initiated connections detected")
            self.print_c2_connections(detected_ips)
        else:
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.GREEN}C2 IP addresses which received/initiated connections not detected{Fore.RESET}")
            logging.info(f"C2 IP addresses which received/initiated connections not detected")

        c2_domains_detected, detected_domains = self.detect_c2_domains(c2hunter_db)

        if c2_domains_detected:
            self.c2_indicators_detected = True
            self.detected_iocs['c2_domain'] = detected_domains
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.RED}C2 domains which received/initiated connections detected{Fore.RESET}")
            logging.info(f"C2 domains which received/initiated connections detected")
            self.print_c2_domains(detected_domains)
        else:
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.GREEN}C2 domains which received/initiated connections not detected{Fore.RESET}")
            logging.info(f"C2 domains which received/initiated connections not detected")

        c2_url_detected, detected_urls = self.detect_c2_urls(c2hunter_db)
        if c2_url_detected:
            self.c2_indicators_detected = True
            self.detected_iocs['c2_url'] = detected_urls
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.RED}C2 related URLs detected{Fore.RESET}")
            logging.info(f"C2 related URLs detected")
            self.print_c2_urls(detected_urls)
        else:
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.GREEN}C2 related URLs not detected{Fore.RESET}")
            logging.info(f"C2 related URLs not detected")

    def detect_c2_ip_addresses(self, c2hunter_db):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Detecting malicious IP addresses which received/initiated connections ...")
        logging.info("Detecting malicious IP addresses which received/initiated connections")

        connection = sqlite3.connect(c2hunter_db)
        cursor = connection.cursor()

        detected_ips = []
        c2_detected = False

        chunk_size = 100 
        ip_chunks = [self.packet_parser.combined_unique_ip_list[i:i+chunk_size] for i in range(0, len(self.packet_parser.combined_unique_ip_list), chunk_size)]

        feodotracker_results = []
        urlhaus_results = []
        threatfox_results = []
        cursor = connection.cursor()

        for chunk in ip_chunks:
            # print(chunk)

            feodotracker_query='''
                        SELECT ip_address FROM feodotracker 
                        WHERE {}'''.format(' OR '.join(["ip_address='{}'".format(ip) for ip in chunk])) 
            # print(feodotracker_query)
            cursor.execute(feodotracker_query)
            feodotracker_results += cursor.fetchall()

            urlhaus_query = '''
                        SELECT url FROM urlhaus
                        WHERE {}'''.format(' OR '.join(["url LIKE '%{}%'".format(ip) for ip in chunk]))
            # print(urlhaus_query)
            cursor.execute(urlhaus_query)
            urlhaus_results += cursor.fetchall()

            threatfox_query = '''
                        SELECT ioc FROM threatfox
                        WHERE {}'''.format(' OR '.join(["ioc LIKE '%{}%'".format(ip) for ip in chunk]))
            # print(threatfox_query)
            cursor.execute(threatfox_query)
            threatfox_results += cursor.fetchall()

        connection.close()

        if feodotracker_results:
            c2_detected = True
            feodotracker_results = [ip[0] for ip in feodotracker_results]

        if urlhaus_results:
            c2_detected = True
            urls = urlhaus_results
            urlhaus_results = []
            for url in urls:
                match = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url[0])
                if match:
                    urlhaus_results.append(match.group(0))
            
        if threatfox_results:
            c2_detected = True
            urls = threatfox_results
            threatfox_results = []
            for url in urls:
                match = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url[0])
                if match:
                    threatfox_results.append(match.group(0))

        detected_ips = list(set(itertools.chain(feodotracker_results, urlhaus_results, threatfox_results)))

        # for ip in detected_ips:
        #     print(ip)

        return c2_detected, detected_ips

    def print_c2_connections(self, detected_ip_iocs):
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Listing detected external connections with C2 servers")
        logging.info(f"Listing detected external connections with C2 servers")
        # table = PrettyTable(["Source IP", "Destination IP"])
        # for src_ip, dst_ip in self.packet_parser.external_connections:
        #     if src_ip in detected_ip_iocs:
        #         table.add_row([src_ip, dst_ip])
        #     if dst_ip in detected_ip_iocs:
        #         table.add_row([src_ip, dst_ip])
        # print(table)

        # TODO : REWORK all_connections/external_connections FROM PACKET PARSER TO INCLUDE PORTS
        for src_ip, dst_ip in self.packet_parser.external_connections:
            if src_ip in detected_ip_iocs:
                print(f">> {Fore.RED}{src_ip}{Fore.RESET} -> {dst_ip}")
            if dst_ip in detected_ip_iocs:
                print(f">> {src_ip} -> {Fore.RED}{dst_ip}{Fore.RESET}")

    def detect_c2_domains(self, c2hunter_db):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Detecting C2 domains which received/initiated connections ...")
        logging.info(
            "Detecting C2 domains which received/initiated connections")

        detected_domains = []
        c2_detected = False

        # TODO

        return c2_detected, detected_domains

    def print_c2_domains(self, detected_domains):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Listing detected domains for C2 servers")
        logging.info(f"Listing detected domains for C2 servers")
        for domain in detected_domains:
            print(f">> {Fore.RED}{domain}{Fore.RESET}")

    def detect_c2_urls(self, c2hunter_db):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Detecting C2 related URLs ...")
        logging.info("Detecting C2 related URLs")

        connection = sqlite3.connect(c2hunter_db)
        cursor = connection.cursor()

        detected_urls = []
        c2_detected = False

        chunk_size = 100 
        url_chunks = [self.packet_parser.unique_urls[i:i+chunk_size] for i in range(0, len(self.packet_parser.unique_urls), chunk_size)]

        urlhaus_results = []
        cursor = connection.cursor()

        for chunk in url_chunks:
            # print(chunk)

            urlhaus_query = '''
                        SELECT url FROM urlhaus
                        WHERE {}'''.format(' OR '.join(["url LIKE '%{}%'".format(url) for url in chunk]))
            # print(urlhaus_query)
            cursor.execute(urlhaus_query)
            urlhaus_results += cursor.fetchall()

        connection.close()
        
        if urlhaus_results:
            c2_detected = True
            detected_urls = [url[0] for url in urlhaus_results]

        return c2_detected, detected_urls

    def print_c2_urls(self, detected_urls):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Listing detected C2 related URLs")
        logging.info(f"Listing detected C2 related URLs")
        for url in detected_urls:
            print(f">> {Fore.RED}{url}{Fore.RESET}")

    # ----------------------------------------------------------------------------------------------------------------

    def detect_crypto_domains(self):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Looking for network traffic to crypto / cryptojacking based sites ...")
        logging.info(f"Looking for network traffic to crypto / cryptojacking based sites")

        detected = False
        detected_domains = []

        for domain in self.packet_parser.domain_names:
            if domain in self.crypto_domains:
                detected = True
                detected_domains.append(domain)

        if detected:
            self.c2_indicators_detected = True
            self.detected_iocs['crypto_domains'] = detected_domains
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

    # ----------------------------------------------------------------------------------------------------------------

    def get_detected_iocs(self):
        return self.detected_iocs