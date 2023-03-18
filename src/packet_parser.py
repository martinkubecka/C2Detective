import json
from scapy.all import *
from scapy.layers import http
import binascii  # binary to ASCII
from time import perf_counter
from ipaddress import ip_address
import logging
import time
from prettytable import PrettyTable
from collections import Counter
import base64


"""
start_time :                                timestamp when packet capture stared    string :        %Y-%m-%d %H:%M:%S
end_time :                                  timestamp when packet capture ended     string :        %Y-%m-%d %H:%M:%S
all_connections/external_connections :      unique connection src-dst IP pairs :    set() :         ((src_ip, dst_ip), ...)
connection_frequency :                      all TCP connections with frequencies :  {} :            {(src_ip, src_port, dst_ip, dst_port):count, ...} 
public_src_ip_list/_dst_ip_list/_ip_list :  all public source/destination IPs :     [] :            [ ip, ip, ... ] 
src_/dst_/combined_/unique_ip_list :        unique source/destination IPs :         [] :            [ ip, ip, ... ]
src_ip_/dst_ip_/all_ip_/counter :           IP quantity :                           {} :            { ip:count, ip:count, ... }
dns_packets :                               extracted packets with DNS layer :      [] :            [packet, packet, ...]
domain_names :                              extrcted domain names from DNS :        set() :         [ domain, domain, ... ]
http_payloads :                             HTTP payloads :                         [] :            [ payload, payload, ... ]
http_sessions :                             HTTP sessions :                         [{}, {}, ...] : [ {src_ip:, src_port:, dst_ip:, dst_port:, http_payload:}, {}, ... ]  
urls :                                      extracted URLs :                        set() :         [ url, url, ... ]
http_requests :                             detailed HTTP requests                  [{}, {}, ...] : [ {src_ip:, src_port:, dst_ip:, dst_port:, method:, host:, path:, url:, user_agent:}, {}, ... ]
"""


class PacketParser:
    def __init__(self, filepath, output_dir, report_extracted_data_option, statistics_option):
        self.logger = logging.getLogger(__name__)
        self.filepath = filepath
        self.packets = self.get_packet_list()  # creates a list in memory

        self.start_time, self.end_time, self.public_src_ip_list, self.public_dst_ip_list, self.public_ip_list, self.all_connections, self.external_connections, self.connection_frequency, self.dns_packets, self.domain_names, self.http_sessions, self.http_payloads, self.unique_urls = self.extract_packet_data()

        self.src_unique_ip_list, self.dst_unique_ip_list, self.combined_unique_ip_list = self.get_unique_public_addresses()
        
        self.src_ip_counter, self.dst_ip_counter, self.all_ip_counter = self.count_public_ip_addresses()

        self.certificates = self.extract_certificates()

        if report_extracted_data_option:
            self.report_dir = output_dir
            self.extracted_data = self.correlate_extracted_data()
            self.extracted_data_to_file()

        self.cli_statistics = statistics_option
        if self.cli_statistics:
            self.print_statistics()

    def get_packet_list(self):
        t_start = perf_counter()
        packets = rdpcap(self.filepath)
        t_stop = perf_counter()
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Packet capture '{self.filepath}' loaded in " +
              "{:.2f}s".format(t_stop - t_start))
        self.logger.info(
            "Packet capture '{self.filepath}' loaded in " + "{:.2f}s".format(t_stop - t_start))
        return packets

    def extract_packet_data(self):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Extracting the start and end timestamps from the provided packet capture ...")
        self.logger.info("Extracting the start and end timestamps from the provided packet capture")
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Extracting public source and destination IP addresses ...")
        self.logger.info("Extracting public source and destination IP addresses")
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Extracting unique connections ...")
        self.logger.info("Extracting unique connections")
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Extracting TCP connections and counting their respective frequencies ...")
        self.logger.info("Extracting TCP connections and counting their respective frequencies")
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Filtering and storing packets with DNS layer ...")
        self.logger.info("Filtering and storing with DNS layer")
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Extracting domain names from DNS queries ...")
        self.logger.info("Extracting domain names from DNS queries")
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Extracting data from HTTP sessions ...")
        self.logger.info("Extracting data from HTTP sessions")

        # store packet capture start and end time
        start_time = None
        end_time = None
        # store connections with their respective frequency 
        connection_frequency = {}
        # store source and destination public IP addresses
        public_src_ip_list = []
        public_dst_ip_list = []
        public_ip_list = []
        # store all and only external connections
        all_connections = set()
        external_connections = set()
        # store filtered DNS packets
        dns_packets = []
        # store extracted domain names from DNS queries
        domain_names = set()
        # store data from HTTP sessions
        http_payloads = []
        http_sessions = []
        unique_urls = set()

        for packet in self.packets:

            if start_time is None:
                # the first packet arrival time (time of capture of the packet)
                start_time = round(float(packet.time), 6) 

            if packet.haslayer(IP):

                src_ip = packet[IP].src
                dst_ip = packet[IP].dst

                if not ip_address(src_ip).is_private:  # append only public IPs
                    public_src_ip_list.append(src_ip)
                    public_ip_list.append(src_ip)

                if not ip_address(dst_ip).is_private:  # append only public IPs
                    public_dst_ip_list.append(dst_ip)
                    public_ip_list.append(dst_ip)

                all_connections.add((src_ip, dst_ip))

                # if src or dst ip is public add it to a separate set
                if not ip_address(src_ip).is_private or not ip_address(dst_ip).is_private:
                    external_connections.add((src_ip, dst_ip))

            if packet.haslayer(TCP):

                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                
                # create connection tuple
                connection = (src_ip, src_port, dst_ip, dst_port)
                
                # update connection count
                if connection in connection_frequency:
                    connection_frequency[connection] += 1
                else:
                    connection_frequency[connection] = 1

            if packet.haslayer(DNS):
                dns_packets.append(packet)

            # extract queried domains from DNS packets with DNSQR layer
            if packet.haslayer(DNSQR):
                try:
                    query = packet[DNSQR].qname.decode('utf-8')  # NOTE: may not be sufficient
                    domain = query[:-1] if query.endswith(".") else query    # remove "." at the end
                    domain_names.add(domain)
                except UnicodeDecodeError:
                    pass

            # check if the packet has an HTTP layer (i.e., is an HTTP request or response)
            if packet.haslayer('HTTPRequest') or packet.haslayer('HTTPResponse'):

                src_ip = packet[IP].src
                src_port = packet[IP].sport
                dst_ip = packet[IP].dst
                dst_port = packet[IP].dport
                http_payload = packet[TCP].payload

                # get HTTP headers either from request or response 
                http_headers = packet.getlayer('HTTPRequest').fields if packet.haslayer('HTTPRequest') else packet.getlayer('HTTPResponse').fields
                http_headers =  self._convert_dict(http_headers)

                # scapy.layers.http.HTTPRequest : https://scapy.readthedocs.io/en/latest/api/scapy.layers.http.html
                http_request = packet.getlayer(http.HTTPRequest)
                if http_request:
                    host = http_request.fields.get('Host')
                    if host and isinstance(host, bytes):
                        host = host.decode() # decode bytes
                    
                    path = http_request.fields.get('Path')
                    if path and isinstance(path, bytes):
                        path = path.decode() # decode bytes
                    
                    user_agent = http_request.fields.get('User_Agent')
                    if user_agent and isinstance(user_agent, bytes):
                        user_agent = user_agent.decode() # decode bytes

                    if host:
                        url = f"{host}{path}"
                        unique_urls.add(url)
                    else:
                        url = ""

                session = dict(
                    src_ip=src_ip,
                    src_port=src_port,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    url=url,
                    path=path,
                    user_agent=user_agent,
                    http_headers=http_headers
                )

                if packet.haslayer('Raw'):
                    payload = packet['Raw'].load
                    http_payloads.append(payload)

                http_sessions.append(session)

            # update the end time of capture with each packet
            end_time = round(float(packet.time), 6)

        # process converted Unix timestamps with microseconds precision
        start_time = datetime.fromtimestamp(start_time).strftime('%Y-%m-%d %H:%M:%S')
        end_time = datetime.fromtimestamp(end_time).strftime('%Y-%m-%d %H:%M:%S')

        return start_time, end_time, public_src_ip_list, public_dst_ip_list, public_ip_list, all_connections, external_connections, connection_frequency, dns_packets, domain_names, http_sessions, http_payloads, unique_urls

    def get_unique_public_addresses(self):
        src_ip_list_set = set(self.public_src_ip_list)
        src_unique_ip_list = (list(src_ip_list_set))

        dst_unique_ip_list_set = set(self.public_dst_ip_list)
        dst_unique_ip_list = (list(dst_unique_ip_list_set))

        combined_ip_list_set = set(self.public_ip_list)
        combined_unique_ip_list = (list(combined_ip_list_set))

        return src_unique_ip_list, dst_unique_ip_list, combined_unique_ip_list

    def count_public_ip_addresses(self):
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Counting the public source and destination IP addresses ...")
        self.logger.info(f"Counting the public source and destination IP addresses")
        src_ip_counter = Counter()
        for ip in self.public_src_ip_list:
            src_ip_counter[ip] += 1

        dst_ip_counter = Counter()
        for ip in self.public_dst_ip_list:
            dst_ip_counter[ip] += 1

        combined_ip_counter = Counter()
        for ip in self.public_ip_list:
            combined_ip_counter[ip] += 1

        return src_ip_counter, dst_ip_counter, combined_ip_counter

    # source: https://stackoverflow.com/questions/72136317/how-to-convert-key-and-value-of-dictionary-from-byte-to-string
    def _convert_dict(self, data):
        if isinstance(data,str):
            return data
        elif isinstance(data,bytes):
            return data.decode()
        elif isinstance(data,dict):
            newdata = {}  # Build a new dict
            for key, val in data.items():
                if isinstance(key,bytes):
                    key = key.decode()
                newdata[key] = self._convert_dict(val)  # Update new dict (and use the val since items() gives it for free)
            return newdata
        elif isinstance(data,list):
            return [self._convert_dict(dt) for dt in data]
        else:
            return data

    def extract_certificates(self):
        cmd = f'tshark -nr {self.filepath} -Y "tls.handshake.certificate" -V'
        output = subprocess.check_output(cmd, shell=True)
        lines = output.decode().splitlines()
        # print(lines)

        certificates = [] #list to store certificates 
        current_cert = {}
        for index, line in enumerate(lines):

                if  line.lstrip(" ").startswith("Source Address"):
                    src_ip = line.lstrip(" ").split(" ")[2]
                    current_cert['src_ip'] = src_ip

                elif line.lstrip(" ").startswith("Destination Address"):
                    dst_ip = line.lstrip(" ").split(" ")[2]
                    current_cert['dst_ip'] = dst_ip
 
                elif line.lstrip(" ").startswith("Source Port"):
                    src_port = line.lstrip(" ").split(" ")[2]
                    current_cert['src_port'] = src_port
 
                elif line.lstrip(" ").startswith("Destination Port"):
                    dst_port = line.lstrip(" ").split(" ")[2]
                    current_cert['dst_port'] = dst_port
 
                elif line.lstrip(" ").startswith("serialNumber"):   
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
        print(f">> Packet capture stared at: {self.start_time}")
        print(f">> Packet capture ended at: {self.end_time}")
        
        print(f">> Number of all connections: {len(self.all_connections)}")
        print(
            f">> Number of external connections: {len(self.external_connections)}")
        print(f">> Number of unique domain names: {len(self.domain_names)}")
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
        print(f">> Number of extracted URLs : {len(self.unique_urls)}")

        print(f">> Number of extracted TLS certificates : {len(self.certificates)}")

    def correlate_extracted_data(self):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Correlating extracted data ...")
        self.logger.info(f"Correlating extracted data")
        extracted_data = {}

        # start and end times of the processed packet capture
        extracted_data['capture_timestamps'] = dict(
            start_time=self.start_time,
            end_time=self.end_time
        )

        # domain names from DNS queries
        extracted_data['extracted_domains'] = list(self.domain_names)

        # unique public source IP address
        extracted_data['public_src_ip_addresses'] = self.src_unique_ip_list

        # unique public source IP address count
        public_src_ip_addresses_count = {}
        for ip, count in self.src_ip_counter.most_common():
            public_src_ip_addresses_count[ip] = count
        extracted_data['public_src_ip_addresses_count'] = public_src_ip_addresses_count

        # unique public destination IP address
        extracted_data['public_dst_ip_addresses'] = self.dst_unique_ip_list

        # unique public destination IP address count
        public_dst_ip_addresses_count = {}
        for ip, count in self.dst_ip_counter.most_common():
            public_dst_ip_addresses_count[ip] = count
        extracted_data['public_dst_ip_addresses_count'] = public_dst_ip_addresses_count

        # unique combined public IP address count
        combined_ip_addresses_count = {}
        for ip, count in self.all_ip_counter.most_common():
            combined_ip_addresses_count[ip] = count
        extracted_data['combined_ip_addresses_count'] = combined_ip_addresses_count

        # extracted URLs
        extracted_data['extracted_urls'] = list(self.unique_urls)

        # extracted HTTP requests
        # extracted_data['http_get_requests'] = self.http_requests

        # extracted HTTP sessions
        extracted_data['http_sessions'] = self.http_sessions

        # extracted data from TLS certificates
        extracted_data['tls_certificates'] = self.certificates

        return json.dumps(extracted_data, indent=4)

    def extracted_data_to_file(self):
        report_output_path = f"{self.report_dir}/extracted_data.json"
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Writing extracted data to '{report_output_path}'")
        self.logger.info(f"Writing extracted data to '{report_output_path}'")

        with open(report_output_path, "w") as output:
            output.write(self.extracted_data)