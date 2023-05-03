import os
import re
import sys
import time
import json
import requests
import logging


class JA3Rules:
    def __init__(self, ja3_rules, ja3_rules_path):
        self.logger = logging.getLogger(__name__)
        self.url_ja3_rules = ja3_rules

        base_relative_path = os.path.dirname(os.path.realpath(sys.argv[0]))
        self.ja3_rules_path = os.path.join(base_relative_path, ja3_rules_path)

    def update_ja3_rules(self):
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Fetching the most up-to-date Proofpoint Emerging Threats JA3 rules ...")
        logging.info(f"Fetching the most up-to-date Proofpoint Emerging Threats JA3 rules ...")
        response = requests.get(self.url_ja3_rules)
        if response.status_code == 200:
            pattern = r'msg:"([^"]*)".*ja3.hash; content:"([^"]*)"'
            ja3_rules = []

            for line in response.iter_lines(decode_unicode=True):
                # apply the regular expression to the line
                match = re.search(pattern, line)

                # if the regular expression matched, extract the msg and content fields
                if match:
                    try:
                        msg = match.group(1)
                        msg = msg.split("- ")[-1]

                        # NOTE : rule 'Fake Firefox Font Update' is not documented, therefore it is not processed 
                        if not msg == "Fake Firefox Font Update":
                            content = match.group(2)
                            entry = dict(
                                type=msg,
                                hash=content
                            )
                            ja3_rules.append(entry)
                    except Exception as e:
                        logging.error(f"Error occurred while parsing fetched JA3 rules", exc_info=True)
                        continue
        else:
            print(
                f"[{time.strftime('%H:%M:%S')}] [ERROR] Error occurred while fetching the Proofpoint Emerging Threats JA3 rules")
            logging.error(f"Error occurred while fetching the Proofpoint Emerging Threats JA3 rules", exc_info=True)
            ja3_rules = []

        # caching fetched JA3 rules
        if not ja3_rules:
            print(
                f"[{time.strftime('%H:%M:%S')}] [ERROR] Retrieving the Proofpoint Emerging Threats JA3 rules was not successful ...")
            logging.error(f"Retrieving the Proofpoint Emerging Threats JA3 rules was not successful")
            print("\nExiting program ...\n")
            sys.exit(1)
        else:
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] Caching fetched Proofpoint Emerging Threats JA3 rules ...")
            logging.info(f"Caching fetched Proofpoint Emerging Threats JA3 rules")
            data = json.dumps({'ja3_rules': ja3_rules}, indent=4)
            with open(self.ja3_rules_path, "w") as output:
                output.write(data)
