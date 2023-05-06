import json
from scapy.all import *
from scapy.layers import http
from time import perf_counter
from ipaddress import ip_address
import logging
import time
from prettytable import PrettyTable
from collections import Counter
import hashlib

"""
start_time :                                timestamp when packet capture stared :  string :        %Y-%m-%d %H:%M:%S
end_time :                                  timestamp when packet capture ended :   string :        %Y-%m-%d %H:%M:%S
connection_frequency :                      grouped TCP connections frequencies :   {} :            {(src_ip, src_port, dst_ip, dst_port):count, ...} 
external_tcp_connections :                  all TCP connections :                   [] :            [ (packet_time, src_ip, src_port, dst_ip, dst_port), ... ]                  
public_src_ip_list/_dst_ip_list/_ip_list :  all public source/destination IPs :     [] :            [ ip, ip, ... ] 
src_/dst_/combined_/unique_ip_list :        unique source/destination IPs :         [] :            [ ip, ip, ... ]
src_ip_/dst_ip_/all_ip_/counter :           IP quantity :                           {} :            { ip:count, ip:count, ... }
dns_packets :                               extracted packets with DNS layer :      [] :            [packet, packet, ...]
domain_names :                              extracted domain names from DNS :        list() :        [ domain, domain, ... ]
http_payloads :                             HTTP payloads :                         [] :            [ payload, payload, ... ]
http_sessions :                             HTTP sessions :                         [{}, {}, ...] : [ {time: ,src_ip:, src_port:, dst_ip:, dst_port:, http_payload:}, {}, ... ]  
unique_urls :                               extracted URLs :                        list() :        [ url, url, ... ]
connections :                               gruped connections :                    tuple :         ( (PROTOCOL SRC_IP:SRC_PORT > DST_IP:DST_PORT), ... )
certificates :                              selected TLS certificate fields :       [] :            [ {src_ip, dst_ip, src_port, dst_port, serialNumber, issuer:{organizationName, stateOrProvinceName, countryName, commonName}, subject:{} }, ...]
"""


class PacketParser:
    def __init__(self, analysis_timestamp, analyst_profile, input_file, output_dir, report_extracted_data_option, statistics_option):
        self.logger = logging.getLogger(__name__)

        self.analysis_timestamp = analysis_timestamp
        self.analyst_profile = analyst_profile
        self.STATISTICS_TOP_COUNT = self.analyst_profile.statistics_top_count

        self.input_file = input_file
        self.output_dir = output_dir

        self.packets = self.get_packet_list()  # creates a list in memory

        self.connections = self.get_connections()
        self.start_time, self.end_time, self.public_src_ip_list, self.public_dst_ip_list, self.public_ip_list, self.external_tcp_connections, self.connection_frequency, self.dns_packets, self.domain_names, self.http_sessions, self.http_payloads, self.unique_urls = self.extract_packet_data()
        self.src_unique_ip_list, self.dst_unique_ip_list, self.combined_unique_ip_list = self.get_unique_public_addresses()
        self.src_ip_counter, self.dst_ip_counter, self.all_ip_counter = self.count_public_ip_addresses()
        self.certificates = self.extract_certificates()
        self.ja3_digests = self.get_ja3_digests()

        self.statistics = self.get_statistics()
        self.extracted_data = self.combine_extracted_data()

        if report_extracted_data_option:
            self.extracted_data_to_file()

        if statistics_option:
            self.print_statistics()

    def get_packet_list(self):
        t_start = perf_counter()
        packets = rdpcap(self.input_file)
        t_stop = perf_counter()
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Packet capture '{self.input_file}' loaded in " +
              "{:.2f}s".format(t_stop - t_start))
        self.logger.info(
            "Packet capture '{self.input_file}' loaded in " + "{:.2f}s".format(t_stop - t_start))
        return packets

    def get_connections(self):
        t_start = perf_counter()
        connections = self.packets.sessions()
        t_stop = perf_counter()
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Packets grouped into connections in " +
              "{:.2f}s".format(t_stop - t_start))
        self.logger.info(
            "Packets grouped into connections in " + "{:.2f}s".format(t_stop - t_start))
        return connections

    def extract_packet_data(self):
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Extracting start and end timestamps from the provided packet capture ...")
        self.logger.info("Extracting start and end timestamps from the provided packet capture")
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Extracting public source and destination IP addresses ...")
        self.logger.info("Extracting public source and destination IP addresses")
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Extracting unique connections ...")
        self.logger.info("Extracting unique connections")
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Extracting TCP connections and counting their respective frequencies ...")
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
        # store all TCP connections
        external_tcp_connections = []
        # store filtered DNS packets
        dns_packets = []
        # store extracted domain names from DNS queries
        domain_names = set()
        # store data from HTTP sessions
        http_payloads = []
        http_sessions = []
        unique_urls = set()

        for packet in self.packets:

            # convert Unix timestamp with microsecond precision
            packet_time = datetime.fromtimestamp(round(float(packet.time), 6)).strftime('%Y-%m-%d %H:%M:%S')

            if start_time is None:
                # the first packet arrival time (time of capture of the packet)
                start_time = packet_time

            if packet.haslayer(IP):

                src_ip = packet[IP].src
                dst_ip = packet[IP].dst

                if not ip_address(src_ip).is_private:  # append only public IPs
                    public_src_ip_list.append(src_ip)
                    public_ip_list.append(src_ip)

                if not ip_address(dst_ip).is_private:  # append only public IPs
                    public_dst_ip_list.append(dst_ip)
                    public_ip_list.append(dst_ip)

            if packet.haslayer(TCP):

                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport

                # if src or dst ip is public, further process this connection
                if not ip_address(src_ip).is_private or not ip_address(dst_ip).is_private:

                    # create connection tuple
                    connection = (src_ip, src_port, dst_ip, dst_port)

                    # update connection count
                    if connection in connection_frequency:
                        connection_frequency[connection] += 1
                    else:
                        connection_frequency[connection] = 1

                    external_tcp_connections.append((packet_time, src_ip, src_port, dst_ip, dst_port))

            if packet.haslayer(DNS):
                dns_packets.append(packet)

            # extract queried domain names from DNS packets with DNSQR layer
            if packet.haslayer(DNSQR):
                try:
                    query = packet[DNSQR].qname.decode('utf-8')  # NOTE: may not be sufficient
                    domain = query[:-1] if query.endswith(".") else query  # remove "." at the end
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
                http_headers = packet.getlayer('HTTPRequest').fields if packet.haslayer(
                    'HTTPRequest') else packet.getlayer('HTTPResponse').fields
                http_headers = self._convert_dict(http_headers)

                # scapy.layers.http.HTTPRequest : https://scapy.readthedocs.io/en/latest/api/scapy.layers.http.html
                http_request = packet.getlayer(http.HTTPRequest)
                if http_request:

                    method = http_request.fields.get('Method')
                    if method and isinstance(method, bytes):
                        method = method.decode()  # decode bytes

                    host = http_request.fields.get('Host')
                    if host and isinstance(host, bytes):
                        host = host.decode()  # decode bytes
                        domain_names.add(host)

                    path = http_request.fields.get('Path')
                    if path and isinstance(path, bytes):
                        path = path.decode()  # decode bytes

                    if host:
                        url = f"{host}{path}"
                        unique_urls.add(url)
                    else:
                        url = ""

                session = dict(
                    timestamp=packet_time,
                    src_ip=src_ip,
                    src_port=src_port,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    method=method,
                    url=url,
                    path=path,
                    http_headers=http_headers
                )

                http_sessions.append(session)

                if packet.haslayer('Raw'):
                    payload = packet['Raw'].load
                    http_payloads.append(payload)
            # update the end time of capture with each packet
            end_time = packet_time

        unique_urls = list(unique_urls)
        domain_names = list(domain_names)

        return start_time, end_time, public_src_ip_list, public_dst_ip_list, public_ip_list, external_tcp_connections, connection_frequency, dns_packets, domain_names, http_sessions, http_payloads, unique_urls

    def get_unique_public_addresses(self):
        src_unique_ip_list = list(set(self.public_src_ip_list))
        dst_unique_ip_list = list(set(self.public_dst_ip_list))
        combined_unique_ip_list = list(set(self.public_ip_list))

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
        if isinstance(data, str):
            return data
        elif isinstance(data, bytes):
            return data.decode()
        elif isinstance(data, dict):
            new_data = {}  # Build a new dict
            for key, val in data.items():
                if isinstance(key, bytes):
                    key = key.decode()
                new_data[key] = self._convert_dict(
                    val)  # Update new dict (and use the val since items() gives it for free)
            return new_data
        elif isinstance(data, list):
            return [self._convert_dict(dt) for dt in data]
        else:
            return data

    def extract_certificates(self):
        cmd = f'tshark -nr {self.input_file} -Y "tls.handshake.certificate" -V'
        output = subprocess.check_output(cmd, shell=True)
        lines = output.decode().splitlines()
        # print(lines)

        certificates = []  # list to store certificates
        current_cert = {}
        certificate_flag = ""
        issuer_fields = {}
        subject_fields = {}

        for index, line in enumerate(lines):

            if line.lstrip(" ").startswith("Source Address"):
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
                serial_number = line.lstrip(" ").split(" ")[1]
                current_cert['serialNumber'] = serial_number

            elif line.lstrip(" ").startswith('issuer'):
                issuer_fields = {}
                certificate_flag = "issuer"

            elif line.lstrip(" ").startswith("subject"):
                subject_fields = {}
                certificate_flag = "subject"

            elif line.lstrip(" ").startswith("rdnSequence"):
                # certificate_fields = re.findall('\((.*?)\)', line.lstrip(" "))[0].split(",")
                rdn_sequence_values = re.findall('\((.*?)\)', line.lstrip(" "))

                if not rdn_sequence_values:
                    try:
                        certificate_fields = line.lstrip(" ").split(" ")[3].split(",")
                    except IndexError:
                        certificate_fields = []
                else:
                    try:
                        certificate_fields = rdn_sequence_values[0].split(",")
                    except IndexError:
                        certificate_fields = []

                # print(certificate_fields)

                for entry in certificate_fields:
                    if "emailAddress" in entry:
                        email_address = entry.split("emailAddress=")[1].replace(")", "")
                        # print(emailAddress)
                        if certificate_flag == "issuer":
                            issuer_fields['emailAddress'] = email_address
                        else:
                            subject_fields['emailAddress'] = email_address

                    elif "commonName" in entry:
                        common_name = entry.split("commonName=")[1].replace(")", "")
                        # print(commonName)
                        if certificate_flag == "issuer":
                            issuer_fields['commonName'] = common_name
                        else:
                            subject_fields['commonName'] = common_name

                    elif "organizationalUnitName" in entry:
                        organizational_unit_name = entry.split("organizationalUnitName=")[1].replace(")", "")
                        # print(organizationalUnitName)
                        if certificate_flag == "issuer":
                            issuer_fields['organizationalUnitName'] = organizational_unit_name
                        else:
                            subject_fields['organizationalUnitName'] = organizational_unit_name

                    elif "organizationName" in entry:
                        organization_name = entry.split("organizationName=")[1].replace(")", "")
                        # print(organizationName)
                        if certificate_flag == "issuer":
                            issuer_fields['organizationName'] = organization_name
                        else:
                            subject_fields['organizationName'] = organization_name

                    elif "localityName" in entry:
                        locality_name = entry.split("localityName=")[1].replace(")", "")
                        # print(localityName)
                        if certificate_flag == "issuer":
                            issuer_fields['localityName'] = locality_name
                        else:
                            subject_fields['localityName'] = locality_name

                    elif "stateOrProvinceName" in entry:
                        state_or_province_name = entry.split("stateOrProvinceName=")[1].replace(")", "")
                        # print(stateOrProvinceName)
                        if certificate_flag == "issuer":
                            issuer_fields['stateOrProvinceName'] = state_or_province_name
                        else:
                            subject_fields['stateOrProvinceName'] = state_or_province_name

                    elif "countryName" in entry:
                        country_name = entry.split("countryName=")[1].replace(")", "")
                        # print(countryName)
                        if certificate_flag == "issuer":
                            issuer_fields['countryName'] = country_name
                        else:
                            subject_fields['countryName'] = country_name

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

    def get_ja3_digests(self):

        ja3_digests = []
        try:
            cmd = f'ja3 --json --any_port {self.input_file}'
            output = subprocess.check_output(cmd, shell=True)

            # parse the JSON output
            ja3_digests = json.loads(output)

            # iterate through each dictionary in the list and convert the timestamp value
            for item in ja3_digests:
                timestamp = datetime.fromtimestamp(round(item['timestamp'], 6)).strftime('%Y-%m-%d %H:%M:%S')
                item['timestamp'] = timestamp

        except Exception as e:
            print(f"[{time.strftime('%H:%M:%S')}] [ERROR] Error occurred while running the 'ja3' application ({e})")
            logging.error(f"Error occurred while running the 'ja3' application ({e})")

        return ja3_digests

    # -------------------------------------------------------------------------------------------

    def get_statistics(self):
        statistics = {}

        statistics["analysis_timestamp"] = self.analysis_timestamp

        with open(self.input_file, 'rb') as f:
            input_file_sha256 = hashlib.sha256()
            for chunk in iter(lambda: f.read(4096), b''):
                input_file_sha256.update(chunk)
        statistics["capture_sha256"] = input_file_sha256.hexdigest()

        statistics["capture_start_time"] = self.start_time
        statistics["capture_end_time"] = self.end_time
        statistics["number_of_external_tcp_connections"] = len(self.external_tcp_connections)
        statistics["number_of_unique_domain_names"] = len(self.domain_names)
        statistics["number_of_unique_public_IP_addresses"] = len(self.combined_unique_ip_list)
        statistics["number_of_HTTP_sessions"] = len(self.http_sessions)
        statistics["number_of_extracted_URLs"] = len(self.unique_urls)
        statistics["number_of_extracted_TLS_certificates"] = len(self.certificates)

        return statistics

    def print_statistics(self):
        print('-' * os.get_terminal_size().columns)
        print(f">> Packet capture SHA256: {self.statistics.get('capture_sha256')}")
        print(f">> Packet capture stared at: {self.statistics.get('capture_start_time')}")
        print(f">> Packet capture ended at: {self.statistics.get('capture_end_time')}")
        print(f">> Number of external TCP connections: {self.statistics.get('number_of_external_tcp_connections')}")
        print(f">> Number of unique domain names: {self.statistics.get('number_of_unique_domain_names')}")
        print(f">> Number of unique public IP addresses: {self.statistics.get('number_of_unique_public_IP_addresses')}")

        print(f">> Top {self.STATISTICS_TOP_COUNT} most common public source IP address")
        table = PrettyTable(["Source IP", "Count"])
        for ip, count in self.src_ip_counter.most_common(self.STATISTICS_TOP_COUNT):
            table.add_row([ip, count])
        print(table)

        print(f">> Top {self.STATISTICS_TOP_COUNT} most common public destination IP address")
        table = PrettyTable(["Destination IP", "Count"])
        for ip, count in self.dst_ip_counter.most_common(self.STATISTICS_TOP_COUNT):
            table.add_row([ip, count])
        print(table)

        print(f">> Number of HTTP sessions: {self.statistics.get('number_of_HTTP_sessions')}")
        print(f">> Number of extracted URLs : {self.statistics.get('number_of_extracted_URLs')}")
        print(
            f">> Number of extracted TLS certificates : {self.statistics.get('number_of_extracted_TLS_certificates')}")

    def combine_extracted_data(self):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Preparing extracted data for output ...")
        self.logger.info(f"Preparing extracted data for output")
        extracted_data = {}

        extracted_data['filepath'] = self.input_file
        extracted_data['analysis_timestamp'] = self.statistics.get("analysis_timestamp")
        extracted_data['capture_sha256'] = self.statistics.get("capture_sha256")
        extracted_data['capture_timestamps'] = dict(
            start_time=self.statistics.get("capture_start_time"),
            end_time=self.statistics.get("capture_end_time")
        )
        extracted_data['number_of_external_tcp_connections'] = self.statistics.get("number_of_external_tcp_connections")
        extracted_data['number_of_unique_domain_names'] = self.statistics.get("number_of_unique_domain_names")
        extracted_data['number_of_unique_public_IP_addresses'] = self.statistics.get(
            "number_of_unique_public_IP_addresses")
        extracted_data['number_of_HTTP_sessions'] = self.statistics.get("number_of_HTTP_sessions")
        extracted_data['number_of_extracted_URLs'] = self.statistics.get("number_of_extracted_URLs")
        extracted_data['number_of_extracted_TLS_certificates'] = self.statistics.get(
            "number_of_extracted_TLS_certificates")

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

        # extracted HTTP sessions
        extracted_data['http_sessions'] = self.http_sessions

        # extracted data from TLS certificates
        extracted_data['tls_certificates'] = self.certificates

        # generated ja3 fingerprint
        extracted_data['ja3_fingerprints'] = self.ja3_digests

        return extracted_data

    def extracted_data_to_file(self):
        report_output_path = f"{self.output_dir}/extracted_data.json"
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Writing extracted data to '{report_output_path}' ...")
        self.logger.info(f"Writing extracted data to '{report_output_path}'")

        with open(report_output_path, "w") as output:
            output.write(json.dumps(self.extracted_data, indent=4))

    def get_extracted_data(self):
        return self.extracted_data

    def get_filepath(self):
        return self.input_file
