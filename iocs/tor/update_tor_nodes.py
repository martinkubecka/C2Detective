import os
import sys
import time
import json
import requests
import logging

class TorNodes:
    def __init__(self, tor_node_list, tor_exit_node_list):
        self.logger = logging.getLogger(__name__)
        # you can only fetch data every 30 minutes
        self.url_tor_node_list = tor_node_list
        self.url_tor_exit_nodes = tor_exit_node_list
        self.tor_iocs_path = f"{os.path.dirname(os.path.realpath(sys.argv[0]))}/iocs/tor/tor_nodes.json"
        
    def update_tor_nodes(self):
        if self.url_tor_node_list and self.url_tor_exit_nodes:
            # fetching all nodes
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] Fetching the most up-to-date Tor node list ...")
            logging.info(f"Fetching the most up-to-date Tor node list ...")
            response = requests.get(self.url_tor_node_list)
            if response.status_code == 200:
                data = response.text
                all_nodes = data.splitlines()
            else:
                print(f"[{time.strftime('%H:%M:%S')}] [ERROR] Error ocurred while fetching Tor node list")
                logging.error(f"Error ocurred while fetching Tor node list", exc_info=True)
                all_nodes = []

            # fetching exit nodes
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] Fetching the most up-to-date Tor exit node list ...")
            logging.info(f"Fetching the most up-to-date Tor exit node list ...")
            response = requests.get(self.url_tor_exit_nodes)
            if response.status_code == 200:
                data = response.text
                exit_nodes = data.splitlines()
            else:
                print(f"[{time.strftime('%H:%M:%S')}] [ERROR] Error ocurred while fetching Tor node list")
                logging.error(f"Error ocurred while fetching Tor node list", exc_info=True)
                exit_nodes = []

            # caching fetched Tor nodes
            if not all_nodes or not exit_nodes:
                print(f"[{time.strftime('%H:%M:%S')}] [ERROR] Retrieving Tor IOCs was not successful")
                logging.error(f"Retrieving Tor IOCs was not successful")
                print("\nExiting program ...\n")
                sys.exit(1)
            else:    
                print(f"[{time.strftime('%H:%M:%S')}] [INFO] Caching fetched Tor exit node lists ...")
                logging.info(f"Caching fetched Tor exit node lists")
                tor_nodes = {'all_nodes': all_nodes, 'exit_nodes': exit_nodes}
                data = json.dumps(tor_nodes, indent=4)
                with open(self.tor_iocs_path, "w") as output:
                    output.write(data)
        else:
            print(f"[{time.strftime('%H:%M:%S')}] [ERROR] URLs for Tor node lists are not present in the config ...")
            logging.error(f"URLs for Tor node lists are not present in the config")
            print("\nExiting program ...\n")
            sys.exit(1)