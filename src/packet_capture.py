from scapy.all import *
import logging


class PacketCapture:
    def __init__(self, sniffing_configuration, output_dir):
        self.logger = logging.getLogger(__name__)
        self.sniffing_configuration = sniffing_configuration
        self.output_dir = output_dir

    def capture_packets(self):
        interface = self.sniffing_configuration.get('interface')
        capture_filter = self.sniffing_configuration.get('filter')
        timeout = self.sniffing_configuration.get('timeout')
        filename = self.sniffing_configuration.get('filename')

        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Capturing packets on the '{interface}' interface for {timeout} seconds ...")
        logging.info(f"Capturing packets on the '{interface}' interface for {timeout} seconds ...")
        packets = sniff(iface=interface, filter=capture_filter, timeout=timeout)

        output_filepath = f"{self.output_dir}/{filename}"
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Writing captured packets to '{output_filepath}' ...")
        logging.info(f"Writing captured packets to '{output_filepath}'")
        wrpcap(output_filepath, packets)

        return output_filepath
