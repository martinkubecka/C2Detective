import logging
import time
import json

class DetectionReporter:
    def __init__(self, output_dir, detected_iocs):
        self.logger = logging.getLogger(__name__)
        self.report_dir = output_dir
        self.detected_iocs = detected_iocs

    def write_detected_iocs_to_file(self):
        report_output_path = f"{self.report_dir}/detected_iocs.json"
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Writing detected IOCs to '{report_output_path}'")
        self.logger.info(f"Writing detected IOCs '{report_output_path}'")

        with open(report_output_path, "w") as output:
            output.write(json.dumps(self.detected_iocs, indent=4))