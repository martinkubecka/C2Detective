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
# import cryptography


class PacketParser:
    def __init__(self, filepath):
        self.logger = logging.getLogger(__name__)
        self.filepath = filepath
        self.packets = self.get_packet_list()  # creates a list in memory

        self.all_connections, self.external_connections = self.extract_unique_connections()
        self.src_ip_list, self.dst_ip_list = self.extract_public_ip_addresses()
        self.rrnames = self.extract_domains()
        self.http_payloads, self.http_sessions = self.get_http_sessions()
        self.urls, self.http_get_requests = self.extract_urls()

        # self.extract_domains_from_certificates()

        self.statistics = True
        if self.statistics:
            self.get_statistics()

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

        for packet in self.packets:
            if 'IP' in packet:
                try:
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst

                    if not ip_address(src_ip).is_private:  # append only public IPs
                        src_ip_list.append(src_ip)

                    if not ip_address(dst_ip).is_private:  # append only public IPs
                        dst_ip_list.append(dst_ip)
                except:
                    pass

        return src_ip_list, dst_ip_list

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
                    rrnames.add(packet.an.rrname.decode('UTF-8'))

        return rrnames

    def get_http_sessions(self):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Extracting data from HTTP sessions ...")
        self.logger.info("Extracting data from HTTP sessions")
        # e.g.: UDP 10.9.23.101:56868 > 10.9.23.23:53 ; TCP 137.184.114.20:80 > 10.9.23.101:58592
        http_payloads = []
        http_sessions = []
        sessions = self.packets.sessions()
        for session in sessions:
            http_payload = ""
            field_entry = []
            for packet in sessions[session]:
                try:
                    if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                        src_ip = packet[IP].src
                        src_port = packet[IP].sport
                        dst_ip = packet[IP].dst
                        dst_port = packet[IP].dport
                        http_payload = packet[TCP].payload

                        # TODO : change to dictionary
                        field_entry.append(src_ip)
                        field_entry.append(src_port)
                        field_entry.append(dst_ip)
                        field_entry.append(dst_port)
                        field_entry.append(http_payload)

                        http_payloads.append(http_payload)
                        http_sessions.append(field_entry)
                        # print(src_ip, src_port, dst_ip, dst_port)
                except:
                    pass

        return http_payloads, http_sessions

    def extract_urls(self):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Extracting data from HTTP GET requests ...")
        self.logger.info("Extracting data from HTTP GET requests")

        http_get_requests = []
        urls = []

        for packet in self.packets:
            if packet.haslayer(http.HTTPRequest):   # process packets which contains HTTP request 

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
                user_agent = user_agent.decode() if user_agent else user_agent  # if User-Agent not None, decode bytes

                # print(f"[ENTRY] : {src_ip} requested {method} {host}{path} | {user_agent}")
                # print(f"[URL] : {host}{path}")

                url = f"{host}{path}"
                urls.append(url)

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
                http_get_requests.append(get_request)

        return urls, http_get_requests


    def get_statistics(self):
        print(f"\n_________________ [ STATISTICS ] _________________")
        print(f">> Number of all connections: {len(self.all_connections)}")
        print(
            f">> Number of external connections: {len(self.external_connections)}")
        print(f">> Number of unique 'rrnames': {len(self.rrnames)}")

        top_count = 3
        print(f">> Top {top_count} most common public source IP address")
        src_ip_counter = Counter()
        for ip in self.src_ip_list:
            src_ip_counter[ip] += 1
        table = PrettyTable(["Source IP", "Count"])
        for ip, count in src_ip_counter.most_common(top_count):
            table.add_row([ip, count])
        print(table)

        print(f">> Top {top_count} most common public destination IP address")
        dst_ip_counter = Counter()
        for ip in self.dst_ip_list:
            dst_ip_counter[ip] += 1
        table = PrettyTable(["Destination IP", "Count"])
        for ip, count in dst_ip_counter.most_common(top_count):
            table.add_row([ip, count])
        print(table)

        print(f">> Number of HTTP sessions: {len(self.http_sessions)}")
        # print(f">> Number of HTTP payloads: {len(self.http_payloads)}")   # compare number with sessions
        # print(f">> Number of HTTP GET requests : {len(self.http_get_requests)}") # compare number with urls
        print(f">> Number of extracted URLs : {len(self.urls)}")

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
