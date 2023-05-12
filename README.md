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
    - [:package: Installing Required Packages and Tools](#package-installing-required-packages-and-tools)
    - [:old\_key: API Keys](#old_key-api-keys)
- [:rotating_light: Notice](#rotating_light-notice)
- [:keyboard: Usage](#keyboard-usage)
- [:placard: List of Features](#placard-list-of-features)
    - [:ballot\_box\_with\_check: Implemented Features](#ballot_box_with_check-implemented-features)
        - [General](#general)
        - [Packet Capture Analysis](#packet-capture-analysis)
        - [Detection](#detection)
        - [IoCs Enrichment](#iocs-enrichment)
    - [:clipboard: To-Do](#clipboard-to-do)
        - [General](#general-1)
        - [Packet Capture Analysis](#packet-capture-analysis-1)
        - [Detection](#detection-1)
        - [IoCs Enrichment](#iocs-enrichment-1)
- [:toolbox: Development](#toolbox-development)
    - [:office: Virtual Environment](#office-virtual-environment)

---

## :memo: Pre-requisites

- the current version requires **Linux** based operating system
- install [Python](https://www.python.org/downloads/) version >= **3.8** < **3.11** (recommended 3.10)
- clone this project with the following command

```
$ git clone https://github.com/martinkubecka/C2Detective.git
```

### :package: Installing Required Packages and Tools

```
$ pip install -r requirements.txt
```

> Note: To learn more about different Scapy v2.x bundles visit https://scapy.readthedocs.io/en/latest/installation.html

- install [wkhtmltopdf](https://wkhtmltopdf.org/) tool that provides a way to convert HTML web pages or documents to PDF
  format
- install [Tshark](https://tshark.dev/setup/install/#installing-tshark-only) which in our case is used for processing packets containg TLS certificate related information

> Note: To find out more about **wkhtmltopdf** or **Tshark**, you can refer to the documentation or support resources provided by your package manager.

### :old_key: API Keys

- enrichment engine uses the following APIs:
    - [AbuseIPDB](https://www.abuseipdb.com/)
    - [AlienVault](https://otx.alienvault.com/)
    - [Shodan](https://www.shodan.io/)
    - [ThreatFox](https://threatfox.abuse.ch/)
    - [URLhaus](https://urlhaus.abuse.ch/)
    - [VirusTotal](https://www.virustotal.com/gui/home/upload)

- if you want to use all the service listed above, add your API keys for `AbuseIPDB`, `VirusTotal` and `Shodan` to
  the `config/config.yml` file as shown in the `config/example.yml`

> Note: You can enable or disable specific enrichment services by modifying the `enrichment_services` section in the
> configuration file `config/config.yml`.

---

## :rotating_light: Notice

- Scapy requires **root** privileges for sniffing
- running *any* python application with root privileges is not recommended for security concerns
- if you want to use provided sniffing option, you can assign `CAP_NET_RAW` and `CAP_NET_ADMIN` capabilities to the
  respective python binary
    - use the following commands before selecting the sniffing option
    - with the `getcap` command, we can verify assigned capabilities

```
$ which python3.10
/usr/bin/python3.10
$ sudo setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' /usr/bin/python3.10
$ getcap /usr/bin/python3.10
/usr/bin/python3.10 cap_net_admin,cap_net_raw=eip
```

> ***Note:*** *Assigning capabilities to the python binary in the virtual environment is not possible because
capabilities can be assigned only to the non-symlink files.*

- do not forget to remove added capabilities, if they are no longer needed
- note that the following command will remove all assigned capabilities

```
$ sudo setcap -r /usr/bin/python3.10
$ getcap /usr/bin/python3.10
<no output>
```

---

## :keyboard: Usage

```
usage: c2detective [-h] [-q] (-i FILENAME | -p) [-c FILE] [-s] [-w] [-o PATH] [-d] [-g] [-e] [-utn] [-ucd] [-ujr]

Application for detecting command and control (C2) communication through network traffic analysis.

options:
  -h, --help                     show this help message and exit
  -q, --quiet                    do not print banner
  -c FILE, --config FILE         configuration file (default: 'config/config.yml')
  -s, --statistics               print packet capture statistics to the console
  -w, --write-extracted          write extracted data to a JSON file
  -o PATH, --output PATH         output directory file path for report files (default: 'reports/')

required options:
  -i FILENAME, --input FILENAME  input file (.cap / .pcap / .pcapng)
  -p, --packet-capture           start packet capture (setup in the configuration file)

enable options:
  -d, --dga                      enable DGA domain detection
  -g, --plugins                  enable plugins for extended detection capabilities
  -e, --enrich-iocs              enable data enrichment

update options:
  -utn, --update-tor-nodes       update tor node lists
  -ucd, --update-crypto-domains  update crypto / cryptojacking based sites list
  -ujr, --update-ja3-rules       update JA3 rules
```

---

## :placard: List of Features

### :ballot_box_with_check: Implemented Features

#### General

- [x] command-line interface (CLI) with argument parsing
- [x] implemented logging
- [x] load configurations from config file
    - [x] enrichment services enabling and their API keys
    - [x] option for setting custom thresholds for detection
- [x] update options for Tor node list, crypto based sites list and Proofpoint ET JA3 rules
    - [x] notify the user if Tor node list, crypto based sites list or Proofpoint ET JA3 rules is out-of-date
- [x] option for packet capturing
- [x] report C2 indicators detection score
- [x] create HTML analysis report containing detailed information about detected C2 IoCs

#### Packet Capture Analysis

- [x] load and parse provided packet capture with Scapy
    - [x] extract various data from loaded packet capture
        - [x] packet capture timestamps
        - [x] public IP addresses
        - [x] unique connections
        - [x] TCP connections and their respective frequencies
        - [x] packets with DNS layer
        - [x] domain names from DNS queries
        - [x] HTTP sessions
        - [x] requested URLs
        - [x] fields of interest from TLS certificates
- [x] show custom packet capture statistics in terminal
- [x] write extracted data from packet capture to a JSON file (`extracted_data.json`)

#### Detection

- [x] detect domain names generated by Domain Generation Algorithms (DGA)
- [x] detect Tor network traffic
- [x] detect outgoing traffic to Tor exit nodes
- [x] detect outgoing traffic to crypto / cryptojacking based sites
- [x] detect connections with excessive frequency
- [x] detect long connection
- [x] detect unusual big HTTP response size
- [x] detect known C2 values in TLS certificates
- [x] detect signs of DNS based covert channels - DNS Tunneling
- [x] detect known malicious JA3 (TLS negotiation) fingerprints
- [x] integrate [C2Hunter](https://github.com/martinkubecka/C2Hunter) as a plugin for detection based on the processed
  threat feeds
    - [x] detect C2 IPs which received or initiated connections
    - [x] detect C2 domain names which received or initiated connections
    - [x] detect requested C2 URLs
- [x] write detected IoCs to a JSON file (`detected_iocs.json`)

#### IoCs Enrichment

- [x] IoCs enrichment with AlienVault
- [x] IoCs enrichment with AbuseIPDB
- [x] IoCs enrichment with Shodan
- [x] IoCs enrichment with ThreatFox
- [x] IoCs enrichment with URLhaus
- [x] IoCs enrichment with VirusTotal
- [x] write enriched IoCs to a JSON file (`enriched_iocs.json`)

### :clipboard: To-Do

- following categories contains features that are in a queue for implementation
- this list is ***not exhaustive*** and additional features will be added during development

#### General

- *no queued tasks at this moment*

#### Packet Capture Analysis

- *no queued tasks at this moment*

#### Detection

- *no queued tasks at this moment*

#### IoCs Enrichment

- *no queued tasks at this moment*

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
[C2Detective]$ virtualenv --python=python3.10 venv
[C2Detective]$ source venv/bin/activate
[C2Detective]$ deactivate
```

---

<div align="right">
<a href="#table-of-contents">[ Table of Contents ]</a>
</div>