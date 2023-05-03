import logging
import time
import json
import os
import sys
from jinja2 import Environment, FileSystemLoader
import datetime
import pdfkit
from bs4 import BeautifulSoup


class DetectionReporter:

    def __init__(self, output_dir, thresholds, c2_indicators_total_count, c2_indicators_count, extracted_data,
                 enriched_iocs, detected_iocs, dga_detection, plugin_c2hunter):
        self.logger = logging.getLogger(__name__)
        self.base_relative_path = os.path.dirname(os.path.realpath(sys.argv[0]))
        self.template_dir_path = os.path.join(self.base_relative_path, "templates")
        self.report_dir = output_dir
        self.html_analysis_report_path = os.path.join(self.report_dir, "analysis_report.html")
        self.pdf_analysis_report_path = os.path.join(self.report_dir, "analysis_report.pdf")
        self.report_output_path = os.path.join(self.report_dir, "detected_iocs.json")
        self.enriched_data_output_path = os.path.join(self.report_dir, "enriched_iocs.json")
        self.thresholds = thresholds
        self.extracted_data = extracted_data
        self.detected_iocs = detected_iocs
        self.enriched_iocs = enriched_iocs
        self.c2_indicators_total_count = c2_indicators_total_count
        self.c2_indicators_count = c2_indicators_count
        self.dga_detection = dga_detection
        self.plugin_c2hunter = plugin_c2hunter

    def write_detected_iocs_to_file(self):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Writing detected IoCs to '{self.report_output_path}' file ...")
        self.logger.info(f"Writing detected IoCs '{self.report_output_path}'")

        with open(self.report_output_path, "w") as output:
            output.write(json.dumps(self.detected_iocs, indent=4))

    def write_enriched_iocs_to_file(self):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Writing enriched IoCs to '{self.enriched_data_output_path}' file ...")
        self.logger.info(f"Writing enriched IoCs '{self.enriched_data_output_path}'")

        with open(self.enriched_data_output_path, "w") as output:
            output.write(json.dumps(self.enriched_iocs, indent=4))

    def create_html_analysis_report(self):
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Creating an HTML analysis report '{self.html_analysis_report_path}' ...")
        self.logger.info(f"Creating an HTML analysis report '{self.html_analysis_report_path}'...")

        # load the Jinja2 template
        env = Environment(loader=FileSystemLoader(self.template_dir_path))
        template = env.get_template("report_template.html")

        current_datetime = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # render the template with the detected_iocs data
        rendered_html = template.render(current_datetime=current_datetime, thresholds=self.thresholds,
                                        c2_indicators_total_count=self.c2_indicators_total_count,
                                        c2_indicators_count=self.c2_indicators_count,
                                        extracted_data=self.extracted_data, detected_iocs=self.detected_iocs,
                                        dga_detection=self.dga_detection, plugin_c2hunter=self.plugin_c2hunter)

        # write the report to a file
        with open(self.html_analysis_report_path, 'w') as f:
            f.write(rendered_html)

    def create_pdf_analysis_report(self):
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Creating a PDF analysis report '{self.pdf_analysis_report_path}' ...")
        self.logger.info(f"Creating a PDF analysis report '{self.pdf_analysis_report_path}'...")

        options = {
            'page-size': 'A3',
            'margin-top': '0.25in',
            'margin-right': '0.25in',
            'margin-bottom': '0.25in',
            'margin-left': '0.25in',
            'orientation': 'Landscape'
        }

        with open(self.html_analysis_report_path) as f:
            soup = BeautifulSoup(f, 'html.parser')

        toc_script = soup.find('script',
                               string=lambda t: 'var headings = document.getElementsByClassName(\'toc-heading\')' in t)
        if toc_script:
            toc_script.decompose()

        pdfkit.from_string(str(soup), self.pdf_analysis_report_path, options=options)
