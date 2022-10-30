# C2Detective

> :construction:   *project in development*    :construction:

---
**Table of Contents**

- [Pre-requisites](#pre-requisites)
    - [Virtual environment](#virtual-environment)
    - [Installing required packages](#installing-required-packages)
    - [API Keys](#api-keys) 
- [Usage](#usage)

---
## Pre-requisites

- clone this project with the following command

```
$ git clone https://github.com/martinkubecka/C2Detective.git
```

### Virtual environment

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

### Installing required packages

```
$ pip install -r requirements.txt
```

> Note: To learn more about different Scapy v2.x bundles visit https://scapy.readthedocs.io/en/latest/installation.html

### API Keys

- enrichment engine uses the following APIs:
  - [AbuseIPDB](https://www.abuseipdb.com/)
  - [VirusTotal](https://www.virustotal.com/gui/home/upload)
  - [SecurityTrails](https://securitytrails.com/)
  - [Shodan](https://www.shodan.io/)

- add your API keys for the services listed above to the `config/config.yml` file as shown in the `config/example.yml` 


---
## Usage

```
usage: c2detective [-h] [-q] [-n NAME] [-c FILE] [-a ACTION] [-e [SERVICE]] [-o FILE] FILENAME

Application for detecting command and control (C2) communication through network traffic analysis.

positional arguments:
  FILENAME                          input file (.cap OR .pcap)

options:
  -h, --help                        show this help message and exit
  -q, --quiet                       don't print the banner and other noise
  -n NAME, --name NAME              analysis keyword (e.g. Trickbot, Mirai, Zeus, ...)
  -c FILE, --config FILE            config file (default: ".config/config.yml")
  -a ACTION, --action ACTION        action to execute [sniffer/...]
  -e [SERVICE], --enrich [SERVICE]  data enrichment, use comma delimeter and double quotes when selecting more
                                    [abuseipdb/securitytrails/virustotal/shodan/all] (default if selected: all)
  -o FILE, --output FILE            report output file
```

---
