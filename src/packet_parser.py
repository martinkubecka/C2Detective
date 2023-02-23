import json
from scapy.all import *
from scapy.layers import http
import pandas as pd
import numpy as np
import binascii  # binary to ASCII
from time import perf_counter
from ipaddress import ip_address
import logging
import time
from prettytable import PrettyTable
from collections import Counter
import base64
# import cryptography

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


class PacketParser:
    def __init__(self, filepath, output_dir, report_iocs, statistics):
        self.logger = logging.getLogger(__name__)
        self.filepath = filepath
        self.packets = self.get_packet_list()  # creates a list in memory

        self.all_connections, self.external_connections = self.extract_unique_connections()

        self.src_ip_list, self.dst_ip_list, self.ip_list = self.extract_public_ip_addresses()
        self.src_unique_ip_list, self.dst_unique_ip_list, self.combined_unique_ip_list = self.get_unique_public_addresses()
        self.src_ip_counter, self.dst_ip_counter, self.all_ip_counter = self.count_public_ip_addresses()

        self.rrnames = self.extract_domains()
        self.http_payloads, self.http_sessions = self.get_http_sessions()
        self.urls, self.http_requests = self.extract_urls()
        self.certificates = self.extract_certificates()
        # self.extract_domains_from_certificates()

        self.report = report_iocs
        if self.report:
            self.report_dir = output_dir
            self.extracted_iocs = self.correlate_iocs()
            self.extracted_iocs_json = json.dumps(
                self.extracted_iocs, indent=4)
            self.iocs_to_file()

        self.cli_statistics = statistics
        if self.cli_statistics:
            self.print_statistics()

    def get_packet_list(self):
        # load_layer('tls') # EXPERIMENTAL
        t_start = perf_counter()
        packets = rdpcap(self.filepath)
        t_stop = perf_counter()
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Packet capture '{self.filepath}' loaded in " +
              "{:.2f}s".format(t_stop - t_start))
        self.logger.info(
            "Packet capture '{self.filepath}' loaded in " + "{:.2f}s".format(t_stop - t_start))
        return packets

    def extract_unique_connections(self):
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Extracting unique connections ...")
        self.logger.info("Extracting unique connections")

        all_connections = set()
        external_connections = set()

        for packet in self.packets:
            if 'IP' in packet:
                ip_layer = packet['IP']  # obtain the IPv4 header
                src_ip = ip_layer.src   # get source ip
                dst_ip = ip_layer.dst   # get destination ip
                all_connections.add((src_ip, dst_ip))
                # if src or dst ip is public add to separate set
                if not ip_address(src_ip).is_private or not ip_address(dst_ip).is_private:
                    external_connections.add((src_ip, dst_ip))

        return all_connections, external_connections

    def extract_public_ip_addresses(self):
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Extracting public source/destination IP addresses ...")
        self.logger.info("Extracting public source/destination IP addresses")

        src_ip_list = []
        dst_ip_list = []
        ip_list = []

        for packet in self.packets:
            if 'IP' in packet:
                try:
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst

                    if not ip_address(src_ip).is_private:  # append only public IPs
                        src_ip_list.append(src_ip)
                        ip_list.append(src_ip)

                    if not ip_address(dst_ip).is_private:  # append only public IPs
                        dst_ip_list.append(dst_ip)
                        ip_list.append(dst_ip)
                
                except:
                    pass

        return src_ip_list, dst_ip_list, ip_list

    def get_unique_public_addresses(self):
        src_ip_list_set = set(self.src_ip_list)
        src_unique_ip_list = (list(src_ip_list_set))

        dst_unique_ip_list_set = set(self.dst_ip_list)
        dst_unique_ip_list = (list(dst_unique_ip_list_set))

        combined_ip_list_set = set(self.ip_list)
        combined_unique_ip_list = (list(combined_ip_list_set))

        return src_unique_ip_list, dst_unique_ip_list, combined_unique_ip_list

    def count_public_ip_addresses(self):
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Counting public source/destination IP addresses ...")
        self.logger.info(f"Counting public source/destination IP addresses")
        src_ip_counter = Counter()
        for ip in self.src_ip_list:
            src_ip_counter[ip] += 1

        dst_ip_counter = Counter()
        for ip in self.dst_ip_list:
            dst_ip_counter[ip] += 1

        combined_ip_counter = Counter()
        for ip in self.ip_list:
            combined_ip_counter[ip] += 1

        return src_ip_counter, dst_ip_counter, combined_ip_counter

    def extract_domains(self):
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Extracting domains from DNS responses ...")
        self.logger.info("Extracting domains from DNS responses")

        rrnames = set()
        # iterate through every packet
        for packet in self.packets:
            # only interested packets with a DNS Round Robin layer
            if packet.haslayer(DNSRR):
                # if the an(swer) is a DNSRR, print the name it replied with
                if isinstance(packet.an, DNSRR):
                    rrname = packet.an.rrname.decode('UTF-8') # NOTE: UTF-8 may not be sufficient
                    domain = rrname[:-1] if rrname.endswith(".") else rrname    # remove "." at the end
                    rrnames.add(domain)

        return rrnames

    def get_http_sessions(self):
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Extracting data from HTTP sessions ...")
        self.logger.info("Extracting data from HTTP sessions")
        # e.g.: UDP 10.9.23.101:56868 > 10.9.23.23:53 ; TCP 137.184.114.20:80 > 10.9.23.101:58592
        http_payloads = []
        http_sessions = []
        sessions = self.packets.sessions()
        for session in sessions:
            http_payload = ""
            # field_entry = []
            for packet in sessions[session]:
                try:
                    if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                        src_ip = packet[IP].src
                        src_port = packet[IP].sport
                        dst_ip = packet[IP].dst
                        dst_port = packet[IP].dport
                        http_payload = packet[TCP].payload

                        entry = dict(
                            src_ip=src_ip,
                            src_port=src_port,
                            dst_ip=dst_ip,
                            dst_port=dst_port,
                            http_payload=http_payload
                        )

                        http_payloads.append(http_payload)
                        http_sessions.append(entry)
                        # print(src_ip, src_port, dst_ip, dst_port)
                except:
                    pass

        return http_payloads, http_sessions

    def extract_urls(self):
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Extracting data from HTTP GET requests ...")
        self.logger.info("Extracting data from HTTP GET requests")

        http_requests = []
        urls = set()

        for packet in self.packets:
            # process packets which contains HTTP request
            if packet.haslayer(http.HTTPRequest):

                http_layer = packet.getlayer(http.HTTPRequest)

                src_ip = packet[IP].src
                src_port = packet[IP].sport
                dst_ip = packet[IP].dst
                dst_port = packet[IP].dport
                http_payload = packet[TCP].payload

                # scapy.layers.http.HTTPRequest : https://scapy.readthedocs.io/en/latest/api/scapy.layers.http.html
                method = http_layer.fields.get('Method')
                method = method.decode() if method else method  # if Method not None, decode bytes

                host = http_layer.fields.get('Host')
                host = host.decode() if host else host  # if Host not None, decode bytes

                path = http_layer.fields.get('Path')
                path = path.decode() if path else path  # if Path not None, decode bytes

                user_agent = http_layer.fields.get('User_Agent')
                # if User-Agent not None, decode bytes
                user_agent = user_agent.decode() if user_agent else user_agent

                # print(f"[ENTRY] : {src_ip} requested {method} {host}{path} | {user_agent}")
                # print(f"[URL] : {host}{path}")

                url = f"{host}{path}"
                urls.add(url)

                get_request = dict(
                    src_ip=src_ip,
                    src_port=src_port,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    # http_payload=http_payload,
                    method=method,
                    host=host,
                    path=path,
                    url=url,
                    user_agent=user_agent
                )
                http_requests.append(get_request)

        return urls, http_requests

    def extract_certificates(self):
        cmd = f'tshark -nr {self.filepath} -Y "tls.handshake.certificate" -V'
        output = subprocess.check_output(cmd, shell=True)
        lines = output.decode().splitlines()
        # print(lines)

        certificates = [] #list to store certificates 
        current_cert = {}
        for index, line in enumerate(lines):
            # line = line.strip()
            # print(line)
            
                if line.lstrip(" ").startswith("serialNumber"):   
                    serialNumber = line.lstrip(" ").split(" ")[1]
                    current_cert['serialNumber'] = serialNumber

                elif line.lstrip(" ").startswith('issuer'):
                    issuer_fields = {}
                    certificate_flag = "issuer"

                elif line.lstrip(" ").startswith("subject"):
                    subject_fields = {}
                    certificate_flag = "subject"

                elif line.lstrip(" ").startswith("rdnSequence"):
                    # certificate_fields = re.findall('\((.*?)\)', line.lstrip(" "))[0].split(",")
                    rdnSequence_values = re.findall('\((.*?)\)', line.lstrip(" "))

                    if not rdnSequence_values:
                        try:
                            certificate_fields = line.lstrip(" ").split(" ")[3].split(",")
                        except IndexError:
                            certificate_fields = []
                    else:
                        try:
                            certificate_fields = rdnSequence_values[0].split(",")
                        except IndexError:
                            certificate_fields = []

                    # print(certificate_fields)

                    for entry in certificate_fields:
                        if "emailAddress" in entry:
                            emailAddress = entry.split("emailAddress=")[1].replace(")", "")
                            # print(emailAddress)
                            if certificate_flag == "issuer":
                                issuer_fields['emailAddress'] = emailAddress
                            else:
                                subject_fields['emailAddress'] = emailAddress

                        elif "commonName" in entry:
                            commonName = entry.split("commonName=")[1].replace(")", "")
                            # print(commonName)
                            if certificate_flag == "issuer":
                                issuer_fields['commonName'] = commonName
                            else:
                                subject_fields['commonName'] = commonName

                        elif "organizationalUnitName" in entry:
                            organizationalUnitName = entry.split("organizationalUnitName=")[1].replace(")", "")
                            # print(organizationalUnitName)
                            if certificate_flag == "issuer":
                                issuer_fields['organizationalUnitName'] = organizationalUnitName
                            else:
                                subject_fields['organizationalUnitName'] = organizationalUnitName

                        elif "organizationName" in entry:
                            organizationName = entry.split("organizationName=")[1].replace(")", "")
                            # print(organizationName)
                            if certificate_flag == "issuer":
                                issuer_fields['organizationName'] = organizationName
                            else:
                                subject_fields['organizationName'] = organizationName

                        elif "localityName" in entry:
                            localityName = entry.split("localityName=")[1].replace(")", "")
                            # print(localityName)
                            if certificate_flag == "issuer":
                                issuer_fields['localityName'] = localityName
                            else:
                                subject_fields['localityName'] = localityName

                        elif "stateOrProvinceName" in entry:
                            stateOrProvinceName = entry.split("stateOrProvinceName=")[1].replace(")", "")
                            # print(stateOrProvinceName)
                            if certificate_flag == "issuer":
                                issuer_fields['stateOrProvinceName'] = stateOrProvinceName
                            else:
                                subject_fields['stateOrProvinceName'] = stateOrProvinceName

                        elif "countryName" in entry:
                            countryName = entry.split("countryName=")[1].replace(")", "")
                            # print(countryName)
                            if certificate_flag == "issuer":
                                issuer_fields['countryName'] = countryName
                            else:
                                subject_fields['countryName'] = countryName
                    
                    if certificate_flag == "issuer":
                        # print(subject_fields)
                        current_cert['issuer'] = issuer_fields
                    
                    elif certificate_flag == "subject":
                        # print(subject_fields)
                        current_cert['subject'] = subject_fields

                elif line.startswith("Frame") or index == len(lines) - 1:
                    if current_cert:
                        certificates.append(current_cert)
                    current_cert = {}

        return certificates

    # -------------------------------------------------------------------------------------------

    def print_statistics(self):
        print('-' * os.get_terminal_size().columns)
        print(f">> Number of all connections: {len(self.all_connections)}")
        print(
            f">> Number of external connections: {len(self.external_connections)}")
        print(f">> Number of unique 'rrnames': {len(self.rrnames)}")
        print(f">> Number of unique public IP addresses: {len(self.combined_unique_ip_list)}")

        top_count = 3
        print(f">> Top {top_count} most common public source IP address")
        table = PrettyTable(["Source IP", "Count"])
        for ip, count in self.src_ip_counter.most_common(top_count):
            table.add_row([ip, count])
        print(table)

        print(f">> Top {top_count} most common public destination IP address")
        table = PrettyTable(["Destination IP", "Count"])
        for ip, count in self.dst_ip_counter.most_common(top_count):
            table.add_row([ip, count])
        print(table)

        print(f">> Number of HTTP sessions: {len(self.http_sessions)}")
        # print(f">> Number of HTTP payloads: {len(self.http_payloads)}")   # compare number with sessions
        # print(f">> Number of HTTP GET requests : {len(self.http_get_requests)}") # compare number with urls
        print(f">> Number of extracted URLs : {len(self.urls)}")

        print(f">> Number of extracted TLS certificates : {len(self.certificates)}")

    def correlate_iocs(self):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Correlating extracted IOCs ...")
        self.logger.info(f"Correlating extracted IOCs")
        iocs = {}

        # rrnames from DNS responses
        extracted_domains = []
        for entry in self.rrnames:
            extracted_domains.append(entry)
        iocs['extracted_domains'] = extracted_domains

        # unique public source IP address
        public_src_ip_addresses = []
        for ip in self.src_unique_ip_list:
            public_src_ip_addresses.append(ip)
        iocs['public_src_ip_addresses'] = public_src_ip_addresses

        # unique public source IP address count
        public_src_ip_addresses_count = {}
        for ip, count in self.src_ip_counter.most_common():
            public_src_ip_addresses_count[ip] = count
        iocs['public_src_ip_addresses_count'] = public_src_ip_addresses_count

        # unique public destination IP address
        public_dst_ip_addresses = []
        for ip in self.dst_unique_ip_list:
            public_dst_ip_addresses.append(ip)
        iocs['public_dst_ip_addresses'] = public_dst_ip_addresses

        # unique public destination IP address count
        public_dst_ip_addresses_count = {}
        for ip, count in self.dst_ip_counter.most_common():
            public_dst_ip_addresses_count[ip] = count
        iocs['public_dst_ip_addresses_count'] = public_dst_ip_addresses_count

        # unique combined public IP address count
        combined_ip_addresses_count = {}
        for ip, count in self.all_ip_counter.most_common():
            combined_ip_addresses_count[ip] = count
        iocs['combined_ip_addresses_count'] = combined_ip_addresses_count

        # extracted URLs
        urls = []
        for url in self.urls:
            urls.append(url)
        iocs['extracted_urls'] = urls

        # extracted HTTP GET requests
        http_get_requests = []
        for entry in self.http_requests:
            http_get_requests.append(entry)
        iocs['http_get_requests'] = http_get_requests

        # extracted HTTP sessions
        # http_sessions = []
        # for entry in self.http_sessions:
        #     # print(entry)
        #     http_sessions.append(entry)
        # iocs['http_sessions'] = http_sessions

        iocs['tls_certificates'] = self.certificates

        return iocs

    def iocs_to_file(self):
        report_output_path = f"{self.report_dir}/extracted_iocs.json"
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Writing extracted IOCs to '{report_output_path}'")
        self.logger.info(f"Writing extracted IOCs to '{report_output_path}'")

        with open(report_output_path, "w") as output:
            output.write(self.extracted_iocs_json)

    # ----------------------------------- EXPERIMENTAL FEATURES -----------------------------------

    # def get_packet_layers(self, packet):
    #     counter = 0
    #     while True:
    #         layer = packet.getlayer(counter)
    #         if layer is None:
    #             break

    #         yield layer
    #         counter += 1

    # source : https://security.stackexchange.com/questions/123851/how-can-i-extract-the-certificate-from-this-pcap-file
    # https://stackoverflow.com/questions/58272264/cannot-read-tls-section-even-after-calling-load-layertls-in-scapy
    # def extract_domains_from_certificates(self):
        # source : https://github.com/secdev/scapy/blob/master/doc/notebooks/tls/notebook2_tls_protected.ipynb

        # (C) <--- (S) ServerHello
        # record2 = TLS(open('samples/02_srv.raw', 'rb').read())
        # print(record2.show())

        # (C) <--- (S) Certificate
        # record3 = TLS(open('samples/03_srv.raw', 'rb').read())
        # print(record3.show())

        # Indeed the certificate may be used with other domains than its CN 'www.github.com'
        # x509c = record3.msg[0].certs[0][1].x509Cert
        # x509c.tbsCertificate.extensions[2].show()

        # 'samples/https_wireshark.pcap'

        # tls_server_hello = self.packets[1526]
        # layer = tls_server_hello.getlayer(TLS)
        # print(tls_server_hello.load)

        # with open('reports/tls_packets_structure.txt', 'w') as output_file:
        #     for packet in self.packets:
        #         try:
        #             packet = TLS(packet.load)
        #             for layer in self.get_packet_layers(packet):
        #                 if not layer.name == "Encrypted Content":
        #                     print(layer.name)
        #             print("----")

        #             # c_hello = packet.getlayer('TLS Handshake - Client Hello')
        #             # print(c_hello.show())

        #             # data = TLS(packet.load)
        #             # print(type(data))
        #             # print(data.show())
        #             # print("\n")

        #             # if 'TLS' in data:
        #             #     x = data.getlayer(TLS)
        #             #     print(x.show())

        #             # output_file.write(data.decode('latin-1'))
        #         except AttributeError as e:
        #             pass
        #         except KeyError as k:
        #             pass

        # for packet in self.packets:
        #     if "TLS" in packet:
        # for layer in packet.layers:
        #     if layer.layer_name == 'tls':
        #         if hasattr(layer, 'x509ce_dnsname'):
        #             print(layer.x509ce_dnsname) # domain

        # for packet in self.packets:
        #     if "TLS" in packet:
        #         # Look for attribute of x509
        #         if hasattr(packet['TLS'], 'x509sat_utf8string'):
        #             print(packet["TLS"])
        #             print(dir(packet['TLS']))

    # source : https://www.linux-magazine.com/Issues/2019/220/Packet-Analysis-with-Scapy
    # def plot_graph(self):
    #     import plotly

    #     xData, yData = [], []

    #     for ip, count in counter.most_common():
    #         xData.append(ip)
    #         yData.append(count)

    #     plotly.offline.plot({"data":[plotly.graph_objs.Bar(x=xData, y=yData)]})
