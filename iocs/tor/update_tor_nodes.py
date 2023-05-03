import os
import sys
import time
import json
import requests
import logging


class TorNodes:
    def __init__(self, tor_node_list, tor_exit_node_list, tor_node_list_path):
        self.logger = logging.getLogger(__name__)
        # you should (can) only fetch data every 30 minutes
        self.tor_node_list_url = tor_node_list
        self.tor_exit_nodes_url = tor_exit_node_list

        base_relative_path = os.path.dirname(os.path.realpath(sys.argv[0]))
        self.tor_iocs_path = os.path.join(base_relative_path, tor_node_list_path)

    def update_tor_nodes(self):
        # fetching all nodes
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Fetching the most up-to-date Tor node list ...")
        logging.info(f"Fetching the most up-to-date Tor node list ...")
        response = requests.get(self.tor_node_list_url)
        if response.status_code == 200:
            data = response.text
            all_nodes = data.splitlines()
        else:
            print(f"[{time.strftime('%H:%M:%S')}] [ERROR] Error occurred while fetching Tor node list")
            logging.error(f"Error occurred while fetching Tor node list", exc_info=True)
            all_nodes = []

        # fetching exit nodes
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Fetching the most up-to-date Tor exit node list ...")
        logging.info(f"Fetching the most up-to-date Tor exit node list ...")
        response = requests.get(self.tor_exit_nodes_url)
        if response.status_code == 200:
            data = response.text
            exit_nodes = data.splitlines()
        else:
            print(f"[{time.strftime('%H:%M:%S')}] [ERROR] Error occurred while fetching Tor exit node list")
            logging.error(f"Error occurred while fetching Tor exit node list", exc_info=True)
            exit_nodes = []

        # caching fetched Tor nodes
        if not all_nodes or not exit_nodes:
            print(f"[{time.strftime('%H:%M:%S')}] [ERROR] Retrieving Tor IoCs was not successful")
            logging.error(f"Retrieving Tor IoCs was not successful")
            print("\nExiting program ...\n")
            sys.exit(1)
        else:
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] Caching fetched Tor node lists ...")
            logging.info(f"Caching fetched Tor node lists")
            tor_nodes = {'all_nodes': all_nodes, 'exit_nodes': exit_nodes}
            data = json.dumps(tor_nodes, indent=4)
            with open(self.tor_iocs_path, "w") as output:
                output.write(data)
