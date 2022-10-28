# C2Detective

> :construction:   *project in development*    :construction:

---
**Table of Contents**

- [Pre-requisites](#pre-requisites)
    - [Virtual environment](#virtual-environment)


---
## Pre-requisites

- clone this project with the following command

```
$ git clone <URL>
```

### Virtual environment

1. use your package manager to install `python-pip` if it is not present on your system
2. install `virtualenv`
3. verify installation by checking the `virtualenv` version
4. inside the project directory create a virtual environment called `venv`
5. activate it by using the `source` command
6. you can deactivate the virtual environment from the parent folder of `venv` directory with the `deactivate` command

```
$ sudo apt-get install python-pip
$ pip install virtualenv
$ virtualenv --version
$ virtualenv --python=python3 venv
$ source venv/bin/activate
$ deactivate
```

### Installing required packages

```
$ pip install -r requirements.txt
```

> Note: Learn more about different Scapy v2.x bundles [here](https://scapy.readthedocs.io/en/latest/installation.html)

---
## Usage

```
usage: c2detective [-h] [-q] [-n NAME] [-c FILE] [-a ACTION] [-o FILE] FILENAME

Application for detecting command and control (C2) communication through network traffic analysis.

positional arguments:
  FILENAME                    input file (.cap OR .pcap)

options:
  -h, --help                  show this help message and exit
  -q, --quiet                 don't print the banner and other noise
  -n NAME, --name NAME        analysis keyword (e.g. Trickbot, Mirai, Zeus, ...)
  -c FILE, --config FILE      config file (default: ".config/config.yml")
  -a ACTION, --action ACTION  action to execute [sniffer/...]
  -o FILE, --output FILE      report output file
```

---
