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
start_time :                                timestamp when packet capture stared :  string :        %Y-%m-%d %H:%M:%S
end_time :                                  timestamp when packet capture ended :   string :        %Y-%m-%d %H:%M:%S
connection_frequency :                      grouped TCP connections frequencies :   {} :            {(src_ip, src_port, dst_ip, dst_port):count, ...} 
external_tcp_connections :                  all TCP connections :                   [] :            [ (packet_time, src_ip, src_port, dst_ip, dst_port), ... ]                  
public_src_ip_list/_dst_ip_list/_ip_list :  all public source/destination IPs :     [] :            [ ip, ip, ... ] 
src_/dst_/combined_/unique_ip_list :        unique source/destination IPs :         [] :            [ ip, ip, ... ]
src_ip_/dst_ip_/all_ip_/counter :           IP quantity :                           {} :            { ip:count, ip:count, ... }
dns_packets :                               extracted packets with DNS layer :      [] :            [packet, packet, ...]
domain_names :                              extrcted domain names from DNS :        list() :        [ domain, domain, ... ]
http_payloads :                             HTTP payloads :                         [] :            [ payload, payload, ... ]
http_sessions :                             HTTP sessions :                         [{}, {}, ...] : [ {time: ,src_ip:, src_port:, dst_ip:, dst_port:, http_payload:}, {}, ... ]  
unique_urls :                               extracted URLs :                        list() :        [ url, url, ... ]
connections :                               gruped connections :                    tuple :         ( (PROTOCOL SRC_IP:SRC_PORT > DST_IP:DST_PORT), ... )
certificates :                              selected TLS certificate fields :       [] :            [ {src_ip, dst_ip, src_port, dst_port, serialNumber, issuer:{organizationName, stateOrProvinceName, countryName, commonName}, subject:{} }, ...]
"""


class DetectionEngine:
    def __init__(self, c2_indicators_total_count, analyst_profile, packet_parser):
        self.logger = logging.getLogger(__name__)
        self.c2_indicators_total_count = c2_indicators_total_count
        self.c2_indicators_count = 0
        self.c2_indicators_detected = False
        self.detected_iocs = {}
        self.detected_iocs['aggregated_ip_addresses'] = set()
        self.detected_iocs['aggregated_domain_names'] = set()
        self.detected_iocs['aggregated_urls'] = set()

        self.packet_parser = packet_parser

        self.CHUNK_SIZE = analyst_profile.chunk_size
        self.MAX_FREQUENCY = len(
            self.packet_parser.packets) * (analyst_profile.MAX_FREQUENCY / 100)
        self.MAX_DURATION = analyst_profile.MAX_DURATION
        self.MAX_HTTP_SIZE = analyst_profile.MAX_HTTP_SIZE
        self.MAX_SUBDOMAIN_LENGTH = analyst_profile.MAX_SUBDOMAIN_LENGTH

        self.whitelisted_domains = self.get_domain_whitelist(
            analyst_profile.domain_whitelist_path)
        self.tor_nodes, self.tor_exit_nodes = self.get_tor_nodes(
            analyst_profile.tor_node_list_path)
        self.crypto_domains = self.get_crypto_domains(
            analyst_profile.crypto_domain_list_path)
        self.c2_http_headers = self.get_c2_http_headers(
            analyst_profile.c2_http_headers_path)
        self.c2_tls_certificate_values = self.get_c2_tls_certificate_values(
            analyst_profile.c2_tls_certificate_values_path)
        self.ja3_rules = self.get_ja3_rules(analyst_profile.ja3_rules_path)

        self.detected_iocs['filepath'] = self.packet_parser.get_filepath()

    def evaluate_detection(self):
        if self.c2_indicators_detected:
            if self.c2_indicators_count < self.c2_indicators_total_count / 2:
                print(f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.YELLOW}Potential Command & Control communication indicators were detected{Fore.RESET}")
            else:
                print(f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.RED}Potential Command & Control communication indicators were detected{Fore.RESET}")
            logging.info(f"Command & Control communication indicators detected")
            print(f">> Number of detected indicators: {self.c2_indicators_count}/{self.c2_indicators_total_count}")
        else:
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.GREEN}Command & Control communication indicators not detected{Fore.RESET}")
            logging.info(f"Command & Control communication indicators not detected")

    def get_c2_http_headers(self, c2_http_headers_path):
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Loading known C2 HTTP headers ...")
        logging.info("Loading known C2 HTTP headers")

        with open(c2_http_headers_path, 'r') as http_headers:
            c2_http_headers = json.load(http_headers)

        return c2_http_headers

    def get_tor_nodes(self, tor_node_list_path):
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Loading cached TOR node list ...")
        logging.info("Loading cached TOR node list")

        with open(tor_node_list_path, 'r') as tor_nodes_iocs:
            data = json.load(tor_nodes_iocs)
            tor_nodes = data['all_nodes']
            exit_nodes = data['exit_nodes']

        return tor_nodes, exit_nodes

    def get_crypto_domains(self, crypto_domain_list_path):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Loading cached crypto / cryptojacking based sites list ...")
        logging.info("Loading cached crypto / cryptojacking based sites list")

        with open(crypto_domain_list_path, 'r') as crypto_domains_iocs:
            data = json.load(crypto_domains_iocs)
            crypto_domains = data['crypto_domains']

        return crypto_domains

    def get_c2_tls_certificate_values(self, c2_tls_certificate_values_path):
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Loading known C2 values in TLS certificates ...")
        logging.info("Loading known C2 values in TLS certificates")

        with open(c2_tls_certificate_values_path, 'r') as tls_values:
            c2_tls_certificate_values = json.load(tls_values)

        return c2_tls_certificate_values

    def get_domain_whitelist(self, domain_whitelist_path):
        whitelisted_domains = []

        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Loading whitelisted domains ...")
        logging.info("Loading whitelisted domains")

        with open(domain_whitelist_path, "r") as whitelist:
            whitelisted_domains = whitelist.read().splitlines()

        return whitelisted_domains

    def get_ja3_rules(self, ja3_rules_path):
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Loading Proofpoint Emerging Threats JA3 rules ...")
        logging.info("Loading Proofpoint Emerging Threats JA3 rules")

        with open(ja3_rules_path, 'r') as ja3_iocs:
            data = json.load(ja3_iocs)
            ja3_rules = data['ja3_rules']

        return ja3_rules

    # ----------------------------------------------------------------------------------------------------------------
    # ------------------------------------------- NETWORK TRAFFIC DETECTION ------------------------------------------
    # ----------------------------------------------------------------------------------------------------------------

    def detect_connections_with_excessive_frequency(self):
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Looking for connections with excessive frequency ...")
        logging.info("Looking for connections with excessive frequency")

        detected = False
        detected_connections = []

        # find connections with excessive frequency
        for connection, count in self.packet_parser.connection_frequency.items():
            if count > self.MAX_FREQUENCY:
                detected = True

                src_ip = connection[0]
                src_port = connection[1]
                dst_ip = connection[2]
                dst_port = connection[3]

                entry = dict(
                    src_ip=src_ip,
                    src_port=src_port,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    frequency=count
                )
                # print(f"Connection {connection} has {count} packets, which is over {threshold:.0f}% of total packets.")
                detected_connections.append(entry)
                self.detected_iocs['aggregated_ip_addresses'].add(src_ip)
                self.detected_iocs['aggregated_ip_addresses'].add(dst_ip)

        if detected:
            self.c2_indicators_detected = True
            self.c2_indicators_count += 1
            self.detected_iocs['excessive_frequency'] = detected_connections
            print(
                f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.RED}Detected connections with excessive frequency{Fore.RESET}")
            logging.info(
                f"Detected connections with excessive frequency. (detected_connections : {detected_connections})")
            self.print_connections_with_excessive_frequency(
                detected_connections)
        else:
            print(
                f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.GREEN}Connections with excessive frequency not detected{Fore.RESET}")
            logging.info(f"Connections with excessive frequency not detected")

    def print_connections_with_excessive_frequency(self, detected_connections):
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Listing connections with excessive frequency")
        logging.info(f"Listing connections with excessive frequency")

        for entry in detected_connections:
            print(f">> {Fore.RED}{entry.get('src_ip')}:{entry.get('src_port')} -> {entry.get('dst_ip')}:{entry.get('dst_port')}{Fore.RESET} = {entry.get('frequency')}/{len(self.packet_parser.packets)} connections")

    def detect_long_connection(self):
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Looking for connections with long duration ...")
        logging.info("Looking for connections with long duration")

        detected = False
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

                    if duration > self.MAX_DURATION:
                        detected = True
                        entry = dict(
                            src_ip=src_ip,
                            src_port=src_port,
                            dst_ip=dst_ip,
                            dst_port=dst_port,
                            duration=int(duration)
                        )
                        detected_connections.append(entry)
                        self.detected_iocs['aggregated_ip_addresses'].add(
                            src_ip)
                        self.detected_iocs['aggregated_ip_addresses'].add(
                            dst_ip)
                else:
                    continue

        if detected:
            self.c2_indicators_detected = True
            self.c2_indicators_count += 1
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
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Listing detected connections with long duration")
        logging.info(f"Listing detected connections with long duration")

        for entry in detected_connections:
            print(
                f">> {Fore.RED}{entry['src_ip']}:{entry['src_port']} -> {entry['dst_ip']}:{entry['dst_port']}{Fore.RESET} = {entry['duration']} seconds")

    def detect_big_HTTP_response_size(self):
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Looking for unusual big HTTP response size ...")
        logging.info("Looking for unusual big HTTP response size")

        detected = False
        detected_connections = []

        for session in self.packet_parser.http_sessions:
            if session.get('http_headers'):
                http_headers = session.get('http_headers')

                if http_headers.get('Content_Length'):
                    content_length = http_headers.get('Content_Length')

                    if int(content_length) > self.MAX_HTTP_SIZE:
                        detected = True
                        detected_connections.append(session)

                        self.detected_iocs['aggregated_ip_addresses'].add(
                            session.get('src_ip'))
                        self.detected_iocs['aggregated_ip_addresses'].add(
                            session.get('dst_ip'))
                        if http_headers.get('Host'):
                            self.detected_iocs['aggregated_domain_names'].add(
                                http_headers.get('Host'))
                        if session.get('url'):
                            self.detected_iocs['aggregated_urls'].add(
                                session.get('url'))

        if detected:
            self.c2_indicators_detected = True
            self.c2_indicators_count += 1
            self.detected_iocs['big_HTTP_response_size'] = detected_connections
            print(
                f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.RED}Detected unusual big HTTP response size{Fore.RESET}")
            logging.info(f"Detected unusual big HTTP response size")
            self.print_connections_with_big_HTTP_response_size(
                detected_connections)
        else:
            print(
                f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.GREEN}Unusual big HTTP response size not detected{Fore.RESET}")
            logging.info(f"Unusual big HTTP response size not detected")

    def print_connections_with_big_HTTP_response_size(self, detected_connections):
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Listing connections with unusual big HTTP response size")
        logging.info(
            f"Listing connections with unusual big HTTP response size")

        for entry in detected_connections:
            print(
                f">> {Fore.RED}{entry['src_ip']}:{entry['src_port']} -> {entry['dst_ip']}:{entry['dst_port']}{Fore.RESET} = {entry['http_headers']['Content_Length']} bytes")

    def detect_known_malicious_HTTP_headers(self):
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Looking for known malicious HTTP headers ...")
        logging.info("Looking for known malicious HTTP headers")

        detected = False
        detected_headers = []

        for session in self.packet_parser.http_sessions:

            if session.get('http_headers').get('Host'):
                host = session.get('http_headers').get('Host')
            else:
                host = None
            if session.get('url'):
                url = session.get('url')
            else:
                url = None

            for key, header_value in session.get('http_headers').items():

                for c2_framework, http_headers in self.c2_http_headers.items():

                    for malicious_header in http_headers:

                        if malicious_header in header_value:
                            detected = True
                            entry = dict(
                                c2_framework=c2_framework,
                                malicious_header=malicious_header,
                                session=session
                            )
                            detected_headers.append(entry)
                            self.detected_iocs['aggregated_ip_addresses'].add(
                                session.get('src_ip'))
                            self.detected_iocs['aggregated_ip_addresses'].add(
                                session.get('dst_ip'))
                            if host:
                                self.detected_iocs['aggregated_domain_names'].add(
                                    host)
                            if url:
                                self.detected_iocs['aggregated_urls'].add(url)

        if detected:
            self.c2_indicators_detected = True
            self.c2_indicators_count += 1
            self.detected_iocs['malicious_HTTP_headers'] = detected_headers
            print(
                f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.RED}Detected known malicious HTTP headers{Fore.RESET}")
            logging.info(
                f"Detected known malicious HTTP headers. (detected_headers : {detected_headers})")
            self.print_malicious_HTTP_headers(detected_headers)
        else:
            print(
                f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.GREEN}Known malicious HTTP headers not detected{Fore.RESET}")
            logging.info(f"Known malicious HTTP headers not detected")

    def print_malicious_HTTP_headers(self, detected_headers):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Listing information about detected malicious HTTP headers")
        logging.info(
            f"Listing information about detected malicious HTTP headers")

        for entry in detected_headers:
            print(
                f">> Found {Fore.RED}'{entry['malicious_header']}'{Fore.RESET} value associated with {Fore.RED}'{entry['c2_framework']}'{Fore.RESET} C2 framework")

    def detect_known_c2_tls_values(self):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Looking for known malicious values in extracted data from TLS certificates ...")
        logging.info(
            "Looking for known malicious values in extracted data from TLS certificates")

        detected_certificates = []

        for entry in self.packet_parser.certificates:

            issuer_values = entry.get("issuer").values()
            subject_values = entry.get("subject").values()

            for c2_framework, malicious_tls_values in self.c2_tls_certificate_values.items():
                detected_value = False
                detected_malicious_value = ""

                for malicious_value in malicious_tls_values:

                    if '+' in malicious_value:
                            value_parts = malicious_value.split('+')
                            
                            is_value_detected = all(
                                part in entry.get('serialNumber') or
                                any(part in value for value in list(issuer_values) + list(subject_values))
                                    for part in value_parts
                                )
                            
                            if is_value_detected:
                                detected_value = True
                                detected_malicious_value = malicious_value
                    else:
                        if malicious_value in entry.get('serialNumber'):
                            detected_value = True
                            detected_malicious_value = malicious_value

                        for value in issuer_values:
                            if malicious_value in value:
                                detected_value = True
                                detected_malicious_value = malicious_value

                        for value in subject_values:
                            if malicious_value in value:
                                detected_value = True
                                detected_malicious_value = malicious_value

            if detected_value:
                entry['c2_framework'] = c2_framework
                entry['malicious_value'] = detected_malicious_value
                detected_certificates.append(entry)
                self.detected_iocs['aggregated_ip_addresses'].add(entry.get('src_ip'))
                self.detected_iocs['aggregated_ip_addresses'].add(entry.get('dst_ip'))

        if detected_certificates:
            self.c2_indicators_detected = True
            self.c2_indicators_count += 1
            self.detected_iocs['malicious_TLS_certificates'] = detected_certificates
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.RED}Detected known malicious values in extracted data from TLS certificates{Fore.RESET}")
            logging.info(
                f"Detected known malicious values in extracted data from TLS certificates. (detected_certificates : {detected_certificates})")
            self.print_known_c2_tls_certificates(detected_certificates)
        else:
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.GREEN}Known malicious values in extracted data from TLS certificates not detected{Fore.RESET}")
            logging.info(
                f"Known malicious values in extracted data from TLS certificates not detected")

    def print_known_c2_tls_certificates(self, detected_certificates):
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Listing information about detected malicious TLS certificates")
        logging.info(f"Listing information about detected malicious TLS certificates")

        for entry in detected_certificates:
            print(f">> Found {Fore.RED}'{entry['malicious_value']}'{Fore.RESET} value associated with {Fore.RED}'{entry['c2_framework']}'{Fore.RESET} C2 framework")

    def detect_tor_traffic(self):
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Looking for indicators of Tor network traffic ...")
        logging.info("Looking for indicators of Tor network traffic")

        detected_tor_traffic = False
        detected_tor_traffic_connections = []
        detected_tor_nodes = set()
        tor_traffic_seen_ips = set()

        detected_tor_traffic_exit_nodes = False
        detected_tor_exit_node_connections = []
        detected_tor_exit_nodes = set()
        tor_exit_nodes_seen_ips = set()

        for connection in self.packet_parser.external_tcp_connections:
            detected_tor_node = False
            detected_tor_exit_node = False

            timestamp = connection[0]
            src_ip = connection[1]
            src_port = connection[2]
            dst_ip = connection[3]
            dst_port = connection[4]

            if src_ip in self.tor_nodes:
                detected_tor_node = True
                detected_tor_nodes.add(src_ip)
            elif dst_ip in self.tor_nodes:
                detected_tor_node = True
                detected_tor_nodes.add(dst_ip)

            if detected_tor_node:
                entry = dict(
                    timestamp=timestamp,
                    src_ip=src_ip,
                    src_port=src_port,
                    dst_ip=dst_ip,
                    dst_port=dst_port
                )

                keys_to_keep = ['src_ip', 'src_port', 'dst_ip', 'dst_port']
                entry_filtered = {k: v for k,
                                  v in entry.items() if k in keys_to_keep}
                entry_frozenset = frozenset(entry_filtered.items())

                if entry_frozenset not in tor_traffic_seen_ips:
                    detected_tor_traffic_connections.append(entry)
                    self.detected_iocs['aggregated_ip_addresses'].add(src_ip)
                    self.detected_iocs['aggregated_ip_addresses'].add(dst_ip)
                    tor_traffic_seen_ips.add(entry_frozenset)
                    detected_tor_traffic = True

            if src_ip in self.tor_exit_nodes:
                detected_tor_exit_node = True
                detected_tor_exit_nodes.add(src_ip)
            elif dst_ip in self.tor_exit_nodes:
                detected_tor_exit_node = True
                detected_tor_exit_nodes.add(dst_ip)

            if detected_tor_exit_node:
                entry = dict(
                    timestamp=timestamp,
                    src_ip=src_ip,
                    src_port=src_port,
                    dst_ip=dst_ip,
                    dst_port=dst_port
                )

                if entry_frozenset not in tor_exit_nodes_seen_ips:
                    detected_tor_exit_node_connections.append(entry)
                    self.detected_iocs['aggregated_ip_addresses'].add(src_ip)
                    self.detected_iocs['aggregated_ip_addresses'].add(dst_ip)
                    tor_exit_nodes_seen_ips.add(entry_frozenset)
                    detected_tor_traffic_exit_nodes = True

        if detected_tor_traffic:
            self.c2_indicators_detected = True
            self.c2_indicators_count += 1
            self.detected_iocs['Tor_nodes'] = list(detected_tor_nodes)
            self.detected_iocs['Tor_network_traffic'] = detected_tor_traffic_connections
            print(
                f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.RED}Detected network traffic to public TOR nodes{Fore.RESET}")
            logging.info(
                f"Detected network traffic to public TOR nodes. (detected_ips : {detected_tor_traffic_connections})")
            self.print_detected_tor_nodes(detected_tor_traffic_connections)
        else:
            print(
                f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.GREEN}Network traffic to public TOR nodes not detected{Fore.RESET}")
            logging.info(f"Network traffic to public TOR nodes not detected")

        if detected_tor_traffic_exit_nodes:
            self.c2_indicators_detected = True
            self.c2_indicators_count += 1
            self.detected_iocs['Tor_exit_nodes'] = list(
                detected_tor_exit_nodes)
            self.detected_iocs['Tor_exit_network_traffic'] = detected_tor_exit_node_connections
            print(
                f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.RED}Detected outgoing network traffic to TOR exit nodes{Fore.RESET}")
            logging.info(
                f"Detected outgoing network traffic to TOR exit nodes. (detected_ips : {detected_tor_exit_node_connections})")
            self.print_detected_tor_exit_nodes(detected_tor_exit_node_connections)
        else:
            print(
                f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.GREEN}Outgoing network traffic to TOR exit nodes not detected{Fore.RESET}")
            logging.info(
                f"Outgoing network traffic to TOR exit nodes not detected")

    def print_detected_tor_nodes(self, detected_connections):
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Listing traffic to public TOR nodes")
        logging.info(f"Listing traffic to public TOR nodes")

        for entry in detected_connections:
            print(f">> {Fore.RED}{entry.get('src_ip')}:{entry.get('src_port')} -> {entry.get('dst_ip')}:{entry.get('dst_port')}{Fore.RESET}")

    def print_detected_tor_exit_nodes(self, detected_connections):
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Listing network traffic to detected TOR exit nodes")
        logging.info(f"Listing network traffic to detected TOR exit nodes")

        for entry in detected_connections:
            print(f">> {Fore.RED}{entry.get('src_ip')}:{entry.get('src_port')} -> {entry.get('dst_ip')}:{entry.get('dst_port')}{Fore.RESET}")

    """
    DGA Detective : https://cossas-project.org/portfolio/dgad/
    - source code: https://github.com/COSSAS/dgad
    - package: https://pypi.org/project/dgad/
    """
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
        mydomains, _ = detective.prepare_domains(
            self.packet_parser.domain_names)
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
                self.detected_iocs['aggregated_domain_names'].add(dga_domain)

        if dga_detected:
            self.c2_indicators_detected = True
            self.c2_indicators_count += 1
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
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Looking for indicators of DNS Tunneling technique ...")
        logging.info("Looking for indicators of DNS Tunneling technique")

        detected = False
        detected_queries = {}

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

                if len(subdomain) > self.MAX_SUBDOMAIN_LENGTH:    # check for long domain names
                    detected = True
                    domain = f"{domain}.{suffix}"   # rebuild domain with TLD

                    if domain in detected_queries:
                        detected_queries[domain]['queries'].add(query)
                    else:
                        detected_queries[domain] = {'queries': {query}}

        for domain in detected_queries:
            queries = list(detected_queries[domain]['queries'])
            detected_queries[domain]['queries'] = queries
            self.detected_iocs['aggregated_domain_names'].update(queries)

        if detected:
            self.c2_indicators_detected = True
            self.c2_indicators_count += 1
            self.detected_iocs['DNS_Tunneling'] = detected_queries
            print(
                f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.RED}Detected DNS Tunneling technique{Fore.RESET}")
            logging.info(
                f"Detected DNS Tunneling technique. (detected_queries : {detected_queries})")
            self.print_dns_tunneling_indicators(detected_queries)
        else:
            print(
                f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.GREEN}DNS Tunneling technique not detected{Fore.RESET}")
            logging.info(f"DNS Tunneling technique not detected")

    def print_dns_tunneling_indicators(self, detected_queries):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Listing information about detected DNS Tunneling technique")
        logging.info(
            f"Listing information about detected DNS Tunneling technique")

        for domain, data in detected_queries.items():
            print(
                f">> Queried {len(data['queries'])} unique subdomains for '{Fore.RED}{domain}{Fore.RESET}'")

    def detect_malicious_ja3_digest(self):
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Looking for known malicious JA3 fingerprints ...")
        logging.info("Looking for known malicious JA3 fingerprints")

        detected = False
        detected_connections = []

        for ja3_dict in self.packet_parser.ja3_digests:
            for ja3_rule in self.ja3_rules:
                # print(f"Comparing {ja3_dict.get('ja3_digest')} and {ja3_rule.get('hash')}")

                if ja3_dict.get('ja3_digest') == ja3_rule.get('hash'):
                    detected = True

                    timestamp = ja3_dict.get('timestamp')
                    ja3 = ja3_dict.get('ja3')
                    ja3_digest = ja3_dict.get('ja3_digest')
                    type = ja3_rule.get('type')
                    src_ip = ja3_dict.get('source_ip')
                    src_port = ja3_dict.get('source_port')
                    dst_ip = ja3_dict.get('destination_ip')
                    dst_port = ja3_dict.get('destination_port')

                    entry = dict(
                        timestamp=timestamp,
                        ja3=ja3,
                        ja3_digest=ja3_digest,
                        type=type,
                        src_ip=src_ip,
                        src_port=src_port,
                        dst_ip=dst_ip,
                        dst_port=dst_port
                    )
                    detected_connections.append(entry)
                    self.detected_iocs['aggregated_ip_addresses'].add(
                        src_ip)
                    self.detected_iocs['aggregated_ip_addresses'].add(
                        dst_ip)

        if detected:
            self.c2_indicators_detected = True
            self.c2_indicators_count += 1
            self.detected_iocs['JA3'] = detected_connections
            print(
                f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.RED}Detected known malicious JA3 fingerprints{Fore.RESET}")
            logging.info(
                f"Detected known malicious JA3 fingerprints. (detected_connections : {detected_connections})")
            self.print_detected_ja3_digists(detected_connections)
        else:
            print(
                f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.GREEN}Known malicious JA3 fingerprints not detected{Fore.RESET}")
            logging.info(f"Known malicious JA3 fingerprints not detected")

    def print_detected_ja3_digists(self, detected_connections):
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Listing information about detected JA3 fingerprints")
        logging.info(f"Listing information about detected JA3 fingerprints")

        print(f">> Found {len(detected_connections)} potentially malicious JA3 fingerprint matches")
        # for entry in detected_connections:
        #     print(f">> '{entry.get('type')}' : {Fore.RED}{entry.get('src_ip')}:{entry.get('src_port')} -> {entry.get('dst_ip')}:{entry.get('dst_port')}{Fore.RESET}")

    def detect_crypto_domains(self):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Looking for network traffic to crypto / cryptojacking based sites ...")
        logging.info(
            f"Looking for network traffic to crypto / cryptojacking based sites")

        detected = False
        detected_domains = []

        for domain in self.packet_parser.domain_names:
            if domain in self.crypto_domains:
                detected = True
                detected_domains.append(domain)
                self.detected_iocs['aggregated_domain_names'].add(domain)

        if detected:
            self.c2_indicators_detected = True
            self.c2_indicators_count += 1
            self.detected_iocs['crypto_domains'] = detected_domains
            print(
                f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.RED}Detected crypto / cryptojacking based sites{Fore.RESET}")
            logging.info(
                f"Detected crypto / cryptojacking based sites (detected_domains : {detected_domains})")
            self.print_crypto_domains(detected_domains)
        else:
            print(
                f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.GREEN}Crypto / cryptojacking based sites not detected{Fore.RESET}")
            logging.info(f"Crypto / cryptojacking based sites not detected")

    def print_crypto_domains(self, detected_domains):
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Listing detected crypto / cryptojacking based sites")
        logging.info(f"Listing detected crypto / cryptojacking based sites")
        for domain in detected_domains:
            print(f">> {Fore.RED}{domain}{Fore.RESET}")
    
    # ----------------------------------------------------------------------------------------------------------------
    # ------------------------------------------------ C2Hunter Plugin -----------------------------------------------
    # ----------------------------------------------------------------------------------------------------------------

    def threat_feeds(self, c2hunter_db):

        c2_ips_detected, detected_ips = self.detect_c2_ip_addresses(
            c2hunter_db)

        if c2_ips_detected:
            self.c2_indicators_detected = True
            self.c2_indicators_count += 1
            self.detected_iocs['c2_ip_address'] = detected_ips
            self.detected_iocs['aggregated_ip_addresses'].update(detected_ips)
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.RED}C2 IP addresses which received/initiated connections detected{Fore.RESET}")
            logging.info(
                f"C2 IP addresses which received/initiated connections detected")
            detected_c2_ip_connections = self.build_c2_ip_connections(
                detected_ips)
            self.detected_iocs['c2_ip_address_connection'] = detected_c2_ip_connections
            self.print_c2_ip_addresses(detected_ips)
        else:
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.GREEN}C2 IP addresses which received/initiated connections not detected{Fore.RESET}")
            logging.info(
                f"C2 IP addresses which received/initiated connections not detected")

        c2_domains_detected, detected_domains = self.detect_c2_domains(c2hunter_db)

        if c2_domains_detected:
            self.c2_indicators_detected = True
            self.c2_indicators_count += 1
            self.detected_iocs['c2_domain'] = detected_domains
            self.detected_iocs['aggregated_domain_names'].update(detected_domains)
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.RED}C2 domains which received/initiated connections detected{Fore.RESET}")
            logging.info(
                f"C2 domains which received/initiated connections detected")
            self.print_c2_domains(detected_domains)
        else:
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.GREEN}C2 domains which received/initiated connections not detected{Fore.RESET}")
            logging.info(
                f"C2 domains which received/initiated connections not detected")

        c2_url_detected, detected_urls = self.detect_c2_urls(c2hunter_db)
        if c2_url_detected:
            self.c2_indicators_detected = True
            self.c2_indicators_count += 1
            self.detected_iocs['c2_url'] = detected_urls
            self.detected_iocs['aggregated_urls'].update(detected_urls)
            self.detected_iocs['c2_http_sessions'] = self.get_c2_http_sessions(
                detected_urls)
            print(
                f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.RED}C2 related URLs detected{Fore.RESET}")
            logging.info(f"C2 related URLs detected")
            self.print_c2_urls(detected_urls)
        else:
            print(
                f"[{time.strftime('%H:%M:%S')}] [INFO] {Fore.GREEN}C2 related URLs not detected{Fore.RESET}")
            logging.info(f"C2 related URLs not detected")

    def detect_c2_ip_addresses(self, c2hunter_db):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Detecting malicious IP addresses which received/initiated connections ...")
        logging.info(
            "Detecting malicious IP addresses which received/initiated connections")

        connection = sqlite3.connect(c2hunter_db)
        cursor = connection.cursor()

        detected_ips = []
        c2_detected = False

        ip_chunks = [self.packet_parser.combined_unique_ip_list[i:i+self.CHUNK_SIZE]
                     for i in range(0, len(self.packet_parser.combined_unique_ip_list), self.CHUNK_SIZE)]

        feodotracker_results = []
        urlhaus_results = []
        threatfox_results = []
        cursor = connection.cursor()

        for chunk in ip_chunks:
            # print(chunk)

            feodotracker_query = '''
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
                match = re.search(
                    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url[0])
                if match:
                    urlhaus_results.append(match.group(0))

        if threatfox_results:
            c2_detected = True
            urls = threatfox_results
            threatfox_results = []
            for url in urls:
                match = re.search(
                    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url[0])
                if match:
                    threatfox_results.append(match.group(0))

        detected_ips = list(
            set(itertools.chain(feodotracker_results, urlhaus_results, threatfox_results)))

        # for ip in detected_ips:
        #     print(ip)

        return c2_detected, detected_ips

    def build_c2_ip_connections(self, detected_ip_iocs):
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Searching for C2 IPs in the grouped connections ...")
        logging.info(f"Searching for C2 IPs in the grouped connections ...")

        detected_c2_ip_connections = []
        seen_ips = set()

        for connection in self.packet_parser.external_tcp_connections:
            timestamp = connection[0]
            src_ip = connection[1]
            src_port = connection[2]
            dst_ip = connection[3]
            dst_port = connection[4]

            for c2_ip_address in detected_ip_iocs:
                if src_ip == c2_ip_address or dst_ip == c2_ip_address:
                    entry = dict(
                        timestamp=timestamp,
                        src_ip=src_ip,
                        src_port=src_port,
                        dst_ip=dst_ip,
                        dst_port=dst_port)

                    keys_to_keep = ['src_ip', 'src_port', 'dst_ip', 'dst_port']
                    entry_filtered = {k: v for k,
                                      v in entry.items() if k in keys_to_keep}
                    entry_frozenset = frozenset(entry_filtered.items())

                    if entry_frozenset not in seen_ips:
                        detected_c2_ip_connections.append(entry)
                        seen_ips.add(entry_frozenset)

        return detected_c2_ip_connections

    def print_c2_ip_addresses(self, detected_ips):
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Listing detected C2 IP addresses")
        logging.info(f"Listing detected C2 IP addresses")

        for c2_ip_address in detected_ips:
            print(f">> {Fore.RED}{c2_ip_address}{Fore.RESET}")

    def detect_c2_domains(self, c2hunter_db):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Detecting C2 domains which received/initiated connections ...")
        logging.info(
            "Detecting C2 domains which received/initiated connections")

        connection = sqlite3.connect(c2hunter_db)
        cursor = connection.cursor()

        detected_domains = []
        c2_detected = False

        domain_chunks = [self.packet_parser.domain_names[i:i+self.CHUNK_SIZE]
                         for i in range(0, len(self.packet_parser.domain_names), self.CHUNK_SIZE)]

        threatfox_results = []

        for chunk in domain_chunks:
            # print(chunk)

            threatfox_query = '''
                            SELECT ioc FROM threatfox 
                            WHERE ioc_type='domain' 
                            AND {}'''.format(' OR '.join(["ioc='{}'".format(domain) for domain in chunk]))
            # print(threatfox_query)
            cursor.execute(threatfox_query)
            threatfox_results += cursor.fetchall()

        connection.close()

        if threatfox_results:
            c2_detected = True
            detected_domains = [domain[0] for domain in threatfox_results]

        return c2_detected, detected_domains

    def print_c2_domains(self, detected_domains):
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Listing detected domains for C2 servers")
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

        url_chunks = [self.packet_parser.unique_urls[i:i+self.CHUNK_SIZE]
                      for i in range(0, len(self.packet_parser.unique_urls), self.CHUNK_SIZE)]

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

    def get_c2_http_sessions(self, detected_urls):
        c2_http_sessions = []

        for session in self.packet_parser.http_sessions:
            for c2_url in detected_urls:
                if session.get('url') == c2_url:
                    c2_http_sessions.append(session)

        return c2_http_sessions

    def print_c2_urls(self, detected_urls):
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Listing detected C2 related URLs")
        logging.info(f"Listing detected C2 related URLs")
        for url in detected_urls:
            print(f">> {Fore.RED}{url}{Fore.RESET}")

    # ----------------------------------------------------------------------------------------------------------------

    def get_detected_iocs(self):
        self.logger.info(f"Preparing detected IOCs for writing to the output file")
        self.detected_iocs['aggregated_ip_addresses'] = list(self.detected_iocs['aggregated_ip_addresses'])
        self.detected_iocs['aggregated_domain_names'] = list(self.detected_iocs['aggregated_domain_names'])
        self.detected_iocs['aggregated_urls'] = list(self.detected_iocs['aggregated_urls'])

        ip_list = self.detected_iocs['aggregated_ip_addresses']
        public_ips = [ip for ip in ip_list if not ip_address(ip).is_private]
        self.detected_iocs['aggregated_ip_addresses'] = public_ips 

        return self.detected_iocs

    def get_c2_indicators_count(self):
        return self.c2_indicators_count