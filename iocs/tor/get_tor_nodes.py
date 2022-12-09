import os
import sys
import requests

# you can only fetch the data every 30 minutes
tor_nodes_list = "https://www.dan.me.uk/torlist/"
response = requests.get(tor_nodes_list)
data = response.text
# returns string, each IP on separate line, split on a new line character
ip_list = data.split("\n")

filepath = f"{os.path.dirname(os.path.realpath(sys.argv[0]))}"
with open(f"{filepath}/tor_nodes_list.txt", "w") as tfile:
    for ip in ip_list:
        tfile.write(f"{ip}\n")

# you can only fetch the data every 30 minutes
tor_exit_nodes_list_url = "https://www.dan.me.uk/torlist/?exit"
response = requests.get(tor_exit_nodes_list_url)
data = response.text
# returns string, each IP on separate line, split on a new line character
ip_list = data.split("\n")

filepath = f"{os.path.dirname(os.path.realpath(sys.argv[0]))}"
with open(f"{filepath}/tor_exit_nodes_list.txt", "w") as tfile:
    for ip in ip_list:
        tfile.write(f"{ip}\n")