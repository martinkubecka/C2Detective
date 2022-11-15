from scapy.all import *
import pandas as pd
import numpy as np
import binascii  # binary to ASCII
from time import perf_counter
from ipaddress import ip_address
import logging
import time


class PacketParser:
    def __init__(self, filepath):
        self.logger = logging.getLogger(__name__)
        self.filepath = filepath
        self.packets = rdpcap(self.filepath)  # creates a list in memory
        # creates a generator, packets are not not stored in memory
        # self.packets = PcapReader(self.filepath)

        self.df_packets = self.packets_to_df()
        self.packets_count, self.top_src_address, self.top_dst_address, self.external_src_addresses, self.external_dst_addresses = self.get_capture_statistcs()
        # self.extract_connections()
        # self.get_domains()
        self.confident_level = 0

    # source : https://github.com/secdevopsai/Packet-Analytics/blob/master/Packet-Analytics.ipynb
    def packets_to_df(self):
        t_start = perf_counter()
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Transforming packet capture to DataFrame object ...")
        self.logger.info("Transforming packet capture to DataFrame object")
        # save field names from IP/TCP/UDP to be used as columns in DataFrame
        ip_fields = [field.name for field in IP().fields_desc]
        tcp_fields = [field.name for field in TCP().fields_desc]
        udp_fields = [field.name for field in UDP().fields_desc]

        # ['version', 'ihl', 'tos', 'len', 'id', 'flags', 'frag', 'ttl', 'proto', 'chksum', 'src', 'dst', 'options', 'time', 'sport', 'dport', 'seq', 'ack', 'dataofs', 'reserved', 'flags', 'window', 'chksum', 'urgptr', 'options', 'payload', 'payload_raw', 'payload_hex']
        dataframe_fields = ip_fields + \
                           ['time'] + tcp_fields + ['payload', 'payload_raw', 'payload_hex']

        # create empty dataframe with defined column names
        df = pd.DataFrame(columns=dataframe_fields)

        # iterate over each packet, but load only the IP (layer 3) fields
        for packet in self.packets[IP]:
            # list of all values contained in a single packet -> one row of DF
            field_values = []

            # add all IP fields to dataframe
            for field in ip_fields:
                if field == 'options':
                    # count the number of options defined in IP Header (field name: options)
                    field_values.append(len(packet[IP].fields[field]))
                else:
                    # add the value of a current field into the list
                    field_values.append(packet[IP].fields[field])

            field_values.append(packet.time)

            layer_type = type(packet[IP].payload)

            # iterate over TCP/UDP (layer 4) fields
            for field in tcp_fields:
                try:
                    if field == 'options':
                        field_values.append(
                            len(packet[layer_type].fields[field]))
                    else:
                        field_values.append(packet[layer_type].fields[field])
                except:
                    field_values.append(None)

            # append different variations of the payload field from ###[ Raw ]### segment
            field_values.append(len(packet[layer_type].payload))  # payload
            field_values.append(
                packet[layer_type].payload.original)  # payload_raw
            field_values.append(binascii.hexlify(
                packet[layer_type].payload.original))  # payload_hex

            # add row to the DF
            df_append = pd.DataFrame([field_values], columns=dataframe_fields)
            df = pd.concat([df, df_append], axis=0)

        # reset Index
        df = df.reset_index()
        # drop old index column
        df = df.drop(columns="index")

        t_stop = perf_counter()
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Packet capture transformed in " + "{:.2f}s".format(t_stop - t_start))
        self.logger.info("Packet capture transformed in " + "{:.2f}s".format(t_stop - t_start))

        return df

    def get_capture_statistcs(self):
        print("\n------------------------------------------------------------")
        print(">> Statistics")

        packets_count = len(self.df_packets)
        print(f">>> Loaded {packets_count} packets")

        top_src_address = self.df_packets['src'].describe()['top']
        print(f">>> Top source address: {top_src_address} ")
        # print(df['src'].describe(),'\n\n')

        # print(f">>> Top external source address: {None} ")

        top_dst_address = self.df_packets['dst'].describe()['top']
        print(f">>> Top destination address: {top_dst_address}")
        # print(df['dst'].describe(),"\n\n")

        # print(f">>> Top external destination address: {None} ")

        unique_src_addresses = self.df_packets['src'].unique()
        unique_src_addresses = unique_src_addresses.tolist()
        external_src_addresses = []
        for adr in unique_src_addresses:
            if not ip_address(adr).is_private:
                external_src_addresses.append(adr)

        unique_dst_addresses = self.df_packets['dst'].unique()
        unique_dst_addresses = unique_dst_addresses.tolist()
        external_dest_addresses = []
        for adr in unique_dst_addresses:
            if not ip_address(adr).is_private:
                external_dest_addresses.append(adr)

        # print(f">>> List of IPs communicating with the top source address:")
        # print(self.df_packets[self.df_packets['src']
        #       == top_src_address]['dst'].unique())
        # print(f">>> List of the unique destination ports for communication with the top source address:")
        # print(self.df_packets[self.df_packets['src']
        #       == top_src_address]['dport'].unique())
        # print(f">>> List of the unique source ports for communication with the top source address:")
        # print(self.df_packets[self.df_packets['src']
        #       == top_src_address]['sport'].unique())

        print("------------------------------------------------------------\n")
        return packets_count, top_src_address, top_dst_address, external_src_addresses, external_dest_addresses

    def extract_connections(self):
        self.connetions = set()
        for packet in self.packets:
            if 'IP' in packet:
                ip_layer = packet['IP']  # obtain the IPv4 header
                self.connetions.add((ip_layer.src, ip_layer.dst))
        print(f">> Number of unique connections: {len(self.connetions)}")
        # print(self.connetions)

    # def get_http_sessions(self):
    #     self.sessions = self.packets.sessions()
    #     for session in self.sessions:
    #         http_payload = ""
    #         for packet in self.sessions[session]:
    #             try:
    #                 if packet[TCP].dport == 80 or packet[TCP].sport == 80:
    #                     print(packet[TCP].payload)
    #             except:
    #                 pass

    def get_domains(self):
        print(">> Extracting DNS responses")
        self.rrnames = set()
        # Let's iterate through every packet
        for packet in self.packets:
            # We're only interested packets with a DNS Round Robin layer
            if packet.haslayer(DNSRR):
                # If the an(swer) is a DNSRR, print the name it replied with.
                if isinstance(packet.an, DNSRR):
                    self.rrnames.add(packet.an.rrname.decode('UTF-8'))
        print(f">>> Number of unique 'rrnames': {len(self.rrnames)}")
        for name in self.rrnames:
            print(name)
