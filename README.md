<p align="center">
<img src="https://github.com/martinkubecka/C2Detective/blob/main/docs/banner.png" alt="Logo">
<p align="center"><b>Application for detecting command and control (C2) communication through network traffic analysis.</b></p><br>

---

<div align="center">
:construction:   <i>project in development</i>    :construction:
</div>

---
<h2 id="table-of-contents">Table of Contents</h2>

- [:memo: Pre-requisites](#memo-pre-requisites)
  - [:package: Installing Required Packages](#package-installing-required-packages)
  - [:old\_key: API Keys](#old_key-api-keys)
- [:keyboard: Usage](#keyboard-usage)
- [:placard: List of Features](#placard-list-of-features)
  - [:ballot\_box\_with\_check: Implemented Features](#ballot_box_with_check-implemented-features)
    - [General](#general)
    - [Packet Capture Analysis](#packet-capture-analysis)
    - [Data Enrichment \& Correlation](#data-enrichment--correlation)
    - [Detection](#detection)
  - [:clipboard: To-Do](#clipboard-to-do)
    - [General](#general-1)
    - [Packet Capture Analysis](#packet-capture-analysis-1)
    - [Data Enrichment \& Correlation](#data-enrichment--correlation-1)
    - [Detection](#detection-1)
- [:toolbox: Development](#toolbox-development)
  - [:office: Virtual Environment](#office-virtual-environment)

---
## :memo: Pre-requisites

- clone this project with the following command

```
$ git clone https://github.com/martinkubecka/C2Detective.git
```

### :package: Installing Required Packages

```
$ pip install -r requirements.txt
```

> Note: To learn more about different Scapy v2.x bundles visit https://scapy.readthedocs.io/en/latest/installation.html

### :old_key: API Keys

- enrichment engine uses the following APIs:
  - [AbuseIPDB](https://www.abuseipdb.com/)
  - [AlienVault](https://otx.alienvault.com/)
  - [CIRCL's BGP Ranking](https://www.circl.lu/projects/bgpranking/)
  - [SecurityTrails](https://securitytrails.com/)
  - [Shodan](https://www.shodan.io/)
  - [ThreatFox](https://threatfox.abuse.ch/)
  - [URLhaus](https://urlhaus.abuse.ch/)
  - [VirusTotal](https://www.virustotal.com/gui/home/upload)

- add your API keys for the services listed above (except for `AlienVault`, `ThreatFox`, `URLhaus` and `CIRCL's BGP Ranking`) to the `config/config.yml` file as shown in the `config/example.yml` 

> ***Warning:*** *Do not use SecurityTrails's enrichment on FREE subscription plan.*

---
## :keyboard: Usage

```
usage: c2detective [-h] [-q] [-c FILE] [-o PATH] [-s] [-w] [-d] [-e] [-utn] [-ucd] FILENAME

Application for detecting command and control (C2) communication through network traffic analysis.

positional arguments:
  FILENAME                       input file (.cap OR .pcap)

options:
  -h, --help                     show this help message and exit
  -q, --quiet                    do not print banner
  -c FILE, --config FILE         configuration file (default: 'config/config.yml')
  -o PATH, --output PATH         output directory file path for report files (default: 'reports/')
  -s, --statistics               print packet capture statistics to the console
  -w, --write-extracted          write extracted data to a JSON file
  -d, --dga-detection            enable DGA domain detection
  -e, --enrich                   enable data enrichment

update options:
  -utn, --update-tor-nodes       update tor nodes list
  -ucd, --update-crypto-domains  update crypto / cryptojacking based sites list
```

---
## :placard: List of Features

### :ballot_box_with_check: Implemented Features

#### General

- [x] command-line interface (CLI) with argument parsing
- [x] implemented logging
- [x] load configurations from config file
  - [x] enrichment services enabling and their API keys
  - [x] option for setting custom thresholds for detecion
- [x] update options for Tor node list and crypto / cryptojacking based sites list
  - [x] notify the user if Tor node list or crypto / cryptojacking based sites list is out-of-date  

#### Packet Capture Analysis

- [x] load and parse provided packet capture with Scapy
  - [x] extract various data from loaded packet capture
    - [x] packet capture timestamps
    - [x] public IP addresses
    - [x] unique connections
    - [x] TCP connections and their respective frequencies
    - [x] packets with DNS layer
    - [x] domains from DNS queries
    - [x] HTTP sessions
    - [x] requested URLs
    - [x] fields of interest from TLS certificates
- [x] show custom packet capture statistics in terminal
- [x] write extracted data from packet capture to JSON file (`extracted_data.json`)

#### Data Enrichment & Correlation 

- [x] data enrichment with AlienVault
- [x] data enrichment with AbuseIPDB
- [x] data enrichment with CIRCL's BGP Ranking
- [x] data enrichment with SecurityTrails
- [x] data enrichment with Shodan
- [x] data enrichment with ThreatFox
- [x] data enrichment with URLhaus
- [x] data enrichment with VirusTotal
- [x] correlate enriched data to one JSON object
- [x] write detected IOCs to JSON file (`detected_iocs.json`)

#### Detection
- [x] detect suspicious domains and hosts based on the enriched data
  - [x] detect malicious IPs which received connections
  - [x] detect malicious IPs which initiated connections
  - [x] detect malicious domains which received connections
  - [x] detect malicious domains which initiated connections
- [x] detect domains generated by Domain Generation Algorithms (DGA)
- [x] detect Tor network traffic
- [x] detect outgoing traffic to Tor exit nodes
- [x] detect outgoing traffic to crypto / cryptojacking based sites
- [x] detect connections with excessive frequency
- [x] detect long connection
- [x] detect unusual big HTML response size 
- [x] detect known C2 default HTTP headers
- [x] detect known C2 values in TLS certificates
- [x] detect signs of DNS based covert channels (DNS Tunneling)

> *currently working on detection features*

### :clipboard: To-Do

- following categories contains features that are in a queue for implementation
- this list is ***not exhaustive*** and additional features will be added during development

#### General

- implement cashing (e.g. database) for enriched data and IOCs
- create final HTML report file containg the detected IOCs 

#### Packet Capture Analysis

- *no queued tasks at this moment*

#### Data Enrichment & Correlation 

- [ ] add [Feodo Tracker](https://feodotracker.abuse.ch/blocklist/) : sharing botnet C&C servers - lists generated every 5 minutes
- [ ] add [SSL Blacklist](https://sslbl.abuse.ch/) : identifying and blacklisting SSL certificates used by botnet C&C servers
- [ ] add [Botvrij.eu](https://www.botvrij.eu/) : provides different sets of open source IOCs
- [ ] add [Binary Defense](https://www.binarydefense.com/banlist.txt) Systems Artillery Threat Intelligence Feed and Banlist Feed 
- [ ] add [C&C Tracker](https://osint.bambenekconsulting.com/feeds/c2-ipmasterlist.txt) : active and non-sinkholed C&C IP addresses

#### Detection

- [ ] detect signs of ICMP based covert channels (ICMP Tunneling)
- [ ] detect signs of beaconing behavior coming in and out of the network
- [ ] implement detection confidence scoring system

---
## :toolbox: Development

- contributions to this project are currently not allowed

### :office: Virtual Environment

1. use your package manager to install `python-pip` if it is not present on your system
2. install `virtualenv`
3. verify installation by checking the `virtualenv` version
4. inside the project directory (`C2Detective`) create a virtual environment called `venv`
5. activate it by using the `source` command
6. you can deactivate the virtual environment from the parent folder of `venv` directory with the `deactivate` command

```
$ sudo apt-get install python-pip
$ pip install virtualenv
$ virtualenv --version
$ cd C2Detective/
[C2Detective]$ virtualenv --python=python3 venv
[C2Detective]$ source venv/bin/activate
[C2Detective]$ deactivate
```

---

<div align="right">
<a href="#table-of-contents">[ Table of Contents ]</a>
</div>