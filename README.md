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
  - [VirusTotal](https://www.virustotal.com/gui/home/upload)
  - [SecurityTrails](https://securitytrails.com/)
  - [Shodan](https://www.shodan.io/)
  - [AlientVault](https://otx.alienvault.com/)
  - [ThreatFox](https://threatfox.abuse.ch/)
  - [CIRCL's BGP Ranking](https://www.circl.lu/projects/bgpranking/)

- add your API keys for the services listed above (except for `AlientVault`, `ThreatFox` and `CIRCL's BGP Ranking`) to the `config/config.yml` file as shown in the `config/example.yml` 

> *Warning: Do not use SecurityTrails's enrichment on FREE subscription plan.*

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
  -e [SERVICES], --enrich [SERVICES]  data enrichment, use comma as a delimeter and double quotes when selecting more [abuseipdb/threatfox/securitytrails/virustotal/shodan/alienvault/bgpranking/all] (default if selected: all)
  -o PATH, --output PATH              output directory file path for report files (default: reports/)
```

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