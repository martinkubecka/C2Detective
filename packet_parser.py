from scapy.all import *


class PacketParser:
    def __init__(self, filepath):
        self.filepath = filepath
        self.packets = rdpcap(self.filepath)    # creates a list in memory
        # creates a generator, packets are not not stored in memory
        # self.packets = PcapReader(self.filepath)
        # -------------- TESTING --------------
        self.extract_connections()
        self.get_domains()

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
