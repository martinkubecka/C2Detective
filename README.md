<p align="center">
<img src="https://github.com/martinkubecka/C2Detective/blob/main/docs/banner.png" alt="Logo">
<p align="center"><b>Application for detecting command and control (C2) communication through network traffic analysis.</b></p><br>

---

<div align="center">
:construction:   <i>project in development</i>    :construction:
</div>

---
<h2 id="table-of-contents">Table of Contents</h2>

- [Pre-requisites](#memo-pre-requisites)
    - [Installing Required Packages](#package-installing-required-packages)
    - [API Keys](#old_key-api-keys) 
- [Usage](#keyboard-usage)
- [List of Features](#placard-list-of-features)
    - [Implemented Features](#ballot_box_with_check-implemented-features)
    - [To-Do](#clipboard-to-do)
- [Development](#toolbox-development)
    - [Virtual Environment](#office-virtual-environment)

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
  - [VirusTotal](https://www.virustotal.com/gui/home/upload)

- add your API keys for the services listed above (except for `AlienVault`, `ThreatFox` and `CIRCL's BGP Ranking`) to the `config/config.yml` file as shown in the `config/example.yml` 

> ***Warning:*** *Do not use SecurityTrails's enrichment on FREE subscription plan.*

---
## :keyboard: Usage

```
usage: c2detective [-h] [-q] [-n NAME] [-c FILE] [-a ACTION] [-e [SERVICES]] [-o PATH] FILENAME

Application for detecting command and control (C2) communication through network traffic analysis.

positional arguments:
  FILENAME                            input file (.cap OR .pcap)

options:
  -h, --help                          show this help message and exit
  -q, --quiet                         don't print the banner and other noise
  -n NAME, --name NAME                analysis keyword (e.g. Trickbot, Mirai, Zeus, ...)
  -c FILE, --config FILE              config file (default: ".config/config.yml")
  -a ACTION, --action ACTION          action to execute [sniffer/...]
  -e [SERVICES], --enrich [SERVICES]  data enrichment, use comma as a delimeter and double quotes when selecting more
                                      [abuseipdb/alienvault/bgpranking/securitytrails/shodan/threatfox/virustotal/all] (default if selected: all)
  -o PATH, --output PATH              output directory file path for report files (default: reports/)
```

---
## :placard: List of Features

### :ballot_box_with_check: Implemented Features

#### General

- [x] command-line interface (CLI) with argument parsing
- [x] implemented logging
- [x] load configurations from config file

#### Packet Capture Analysis

- [x] load and parse packet capture with Scapy
- [x] extract various IOCs
  - [x] unique connections
  - [x] public IP addresses
  - [x] domains from DNS responses
  - [x] HTTP payloads
  - [x] requested URLs
- [x] show custom packet capture statistics in terminal
- [x] write extracted IOCs to JSON file
  - [x] public IP addresses and their count
  - [x] domains from DNS responses
  - [x] HTTP GET requests
  - [x] requested URLs

#### Data Enrichment & Correlation 

- [x] data enrichment with AlienVault
- [x] data enrichment with AbuseIPDB
- [x] data enrichment with CIRCL's BGP Ranking
- [x] data enrichment with SecurityTrails
- [x] data enrichment with Shodan
- [x] data enrichment with ThreatFox
- [x] data enrichment with VirusTotal
- [x] correlating enriched data to one JSON object
- [x] write correlated enriched data to the output report file

#### Detection

- *currently working on these features*


### :clipboard: To-Do

- following categories contains features that are in a queue for implementation
- this list is ***not exhaustive*** and additional features will be added during development

#### General

- *no queued tasks at this moment*

#### Packet Capture Analysis

- [ ] extract domains from HTTPs X509 certificates

#### Data Enrichment & Correlation 

- [ ] add C&C Tracker : active and non-sinkholed C&C IP addresses (https://osint.bambenekconsulting.com/feeds/c2-ipmasterlist.txt)
- [ ] add Feodo Tracker : sharing botnet C&C servers - lists generated every 5 minutes (https://feodotracker.abuse.ch/blocklist/)
- [ ] add SSL Blacklist (SSLBL) : identifying and blacklisting SSL certificates used by botnet C&C servers (https://sslbl.abuse.ch/)
- [ ] add URLhaus : sharing malicious URLs that are being used for malware distribution (https://urlhaus.abuse.ch/)
- [ ] add Botvrij.eu : provides different sets of open source IOCs (https://www.botvrij.eu/ ; https://www.botvrij.eu/data/)
- [ ] add Binary Defense Systems Artillery Threat Intelligence Feed and Banlist Feed (https://www.binarydefense.com/banlist.txt)

#### Detection

- [ ] detect suspicious domains and hosts based on the enriched and correlated data
  - [ ] detect malicious domains which received connections
  - [ ] detect malicious domains which initiated connections
  - [ ] detect malicious IPs which received connections
  - [ ] detect malicious IPs which initiated connections
- [ ] detect domains generated by Domain Generation Algorithms (DGA)
- [ ] detect known malicious User-Agents 
- [ ] detect connections with excessive frequency
- [ ] detect long connection
- [ ] detect signs of beaconing behavior comming in and out of the network
- [ ] detect signs of DNS based covert channels (DNS Tunneling)
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