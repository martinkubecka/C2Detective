from scapy.all import *
import pandas as pd
import numpy as np
import binascii  # binary to ASCII
from time import perf_counter
from ipaddress import ip_address
import logging
import time
from prettytable import PrettyTable
from collections import Counter


class PacketParser:
    def __init__(self, filepath):
        self.logger = logging.getLogger(__name__)
        self.filepath = filepath
        self.packets = self.get_packet_list()  # creates a list in memory

        self.all_connections, self.external_connections = self.extract_unique_connections()
        self.src_ip_list, self.dst_ip_list = self.extract_public_ip_addresses()
        self.rrnames = self.extract_domains()
        self.http_payloads = self.get_http_payloads()

        self.statistics = True
        if self.statistics:
            self.get_statistics()

    def get_packet_list(self):
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

    def get_http_payloads(self):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Extracting HTTP payloads ...")
        self.logger.info("Extracting HTTP payloads")
        # e.g.: UDP 10.9.23.101:56868 > 10.9.23.23:53 ; TCP 137.184.114.20:80 > 10.9.23.101:58592
        http_payloads = []
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

                        field_entry.append(src_ip)
                        field_entry.append(src_port)
                        field_entry.append(dst_ip)
                        field_entry.append(dst_port)
                        field_entry.append(http_payload)

                        http_payloads.append(http_payload)
                        # print(src_ip, src_port, dst_ip, dst_port)
                except:
                    pass

        return http_payloads

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

        print(f">> Number of HTTP payloads: {len(self.http_payloads)}")
