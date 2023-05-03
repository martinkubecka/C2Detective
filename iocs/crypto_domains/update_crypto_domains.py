import os
import sys
import time
import json
import requests
import logging


class CryptoDomains:
    def __init__(self, crypto_domains, crypto_domain_list_path):
        self.logger = logging.getLogger(__name__)
        self.url_crypto_domains = crypto_domains

        base_relative_path = os.path.dirname(os.path.realpath(sys.argv[0]))
        self.crypto_domains_iocs_path = os.path.join(base_relative_path, crypto_domain_list_path)

    def update_crypto_domains(self):
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Fetching the most up-to-date crypto / cryptojacking based sites list ...")
        logging.info(f"Fetching the most up-to-date crypto / cryptojacking based sites list ...")
        response = requests.get(self.url_crypto_domains)
        if response.status_code == 200:
            response_content = response.content.decode("utf-8")
            response_data = response_content.split("\n")
            crypto_domains = []
            for line in response_data:
                # retrieved content has a header created from '#' symbols
                if not line.startswith("#") and len(line) > 0:
                    crypto_domains.append(line)
        else:
            print(
                f"[{time.strftime('%H:%M:%S')}] [ERROR] Error ocurred while fetching crypto / cryptojacking based sites list")
            logging.error(f"Error ocurred while fetching crypto / cryptojacking based sites list", exc_info=True)
            crypto_domains = []

            # caching fetched crypto domain names
        if not crypto_domains:
            print(
                f"[{time.strftime('%H:%M:%S')}] [ERROR] Retrieving crypto / cryptojacking based sites list was not successful ...")
            logging.error(f"Retrieving crypto / cryptojacking based sites list was not successful")
            print("\nExiting program ...\n")
            sys.exit(1)
        else:
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] Caching fetched crypto / cryptojacking based sites list ...")
            logging.info(f"Caching fetched crypto / cryptojacking based sites list")
            data = json.dumps({'crypto_domains': crypto_domains}, indent=4)
            with open(self.crypto_domains_iocs_path, "w") as output:
                output.write(data)
