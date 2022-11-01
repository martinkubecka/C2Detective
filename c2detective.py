import argparse
import sys
import os
import platform
import yaml
import logging
import time


from src.analyst_profile import AnalystProfile
from src.packet_parser import PacketParser
from src.data_enrichment import Enrichment

#######################################################################################################################################################################
# TODO
# [1] General
# -- 
#
# [2] Enrichment
# -- BGP Ranking : detect any malicious activities of a specific AS number (https://www.circl.lu/projects/bgpranking/)
# -- AlientVault DirectConnect API
# ---- https://otx.alienvault.com/api ; https://otx.alienvault.com/assets/static/external_api.html ; https://rapidapi.com/raygorodskij/api/AlienVault/details
# -- ThreatFox : sharing IOCs associated with malware (https://threatfox.abuse.ch/
#
# # [3] Analysis
# --
#
# [4] Detection
# -- implement detection confidence scoring system
# -- Feodo Tracker : sharing botnet C&C servers - lists generated every 5 minutes (https://feodotracker.abuse.ch/blocklist/)
# -- SSL Blacklist (SSLBL) : identifying and blacklisting SSL certificates used by botnet C&C servers (https://sslbl.abuse.ch/)
# -- URLhaus : sharing malicious URLs that are being used for malware distribution (https://urlhaus.abuse.ch/)
# -- C&C Tracker : active and non-sinkholed C&C IP addresses (https://osint.bambenekconsulting.com/feeds/c2-ipmasterlist.txt)
# -- Botvrij.eu provides different sets of open source IOCs (https://www.botvrij.eu/ ; https://www.botvrij.eu/data/)
# -- Binary Defense Systems Artillery Threat Intelligence Feed and Banlist Feed (https://www.binarydefense.com/banlist.txt)
#######################################################################################################################################################################


def banner():
    print(r"""
   ____ ____  ____       _            _   _
  / ___|___ \|  _ \  ___| |_ ___  ___| |_(_)_   _____
 | |     __) | | | |/ _ \ __/ _ \/ __| __| \ \ / / _ \
 | |___ / __/| |_| |  __/ ||  __/ (__| |_| |\ V /  __/
  \____|_____|____/ \___|\__\___|\___|\__|_| \_/ \___|

    """)


def is_platfrom_supported():
    machine_platfrom = platform.system().lower()
    if not machine_platfrom.startswith('linux'):
        print("\n[{time.strftime('%H:%M:%S')}] [CRITICAL] Unsupported platform.")
        logging.critical(f"Unsupported platform")
        print("\nExiting program ...\n")
        sys.exit(1)


def is_valid_file(filename, filetype):
    if not os.path.exists(filename):
        print(
            f"[{time.strftime('%H:%M:%S')}] [ERROR] Provided file '{filename}' does not exist.")
        logging.error(f"Provided file '{filename}' does not exist")
        print("\nExiting program ...\n")
        sys.exit(1)
    else:
        if filetype == "pcap":  # check if the filetype is .pcap or .cap
            if not filename.endswith(".pcap") or filename.endswith(".cap"):
                print(
                    f"[{time.strftime('%H:%M:%S')}] [ERROR] Provided file '{filename}' is not a pcap/cap file.")
                logging.error(
                    f"Provided file '{filename}' is not a pcap/cap file")
                print("\nExiting program ...\n")
                sys.exit(1)
        if filetype == "yml":
            if not filename.endswith(".yml") or filename.endswith(".yaml"):
                print(
                    f"[{time.strftime('%H:%M:%S')}] [ERROR] Provided file '{filename}' is not a yaml file.")
                logging.error(f"Provided file '{filename}' is not a yaml file")
                print("\nExiting program ...\n")
                sys.exit(1)
    return True


def load_config(filename):
    with open(filename, "r") as ymlfile:
        config = yaml.safe_load(ymlfile)
    return config


def arg_formatter():
    """
    source : https://stackoverflow.com/questions/52605094/python-argparse-increase-space-between-parameter-and-description
    """
    def formatter(prog): return argparse.HelpFormatter(
        prog, max_help_position=52)
    return formatter


def parse_arguments():
    parser = argparse.ArgumentParser(formatter_class=arg_formatter(), prog='c2detective',
                                     description='Application for detecting command and control (C2) '
                                                 'communication through network traffic analysis.')

    parser.add_argument(
        '-q', '--quiet', help="don't print the banner and other noise", action='store_true')

    # parser.add_argument('-i', help='input file (.cap OR .pcap)', metavar='FILE', required=True,
    #                     type=lambda file: is_valid_file(file))
    # parser.add_argument('-i', '--input', metavar='FILE',
    #                     help='input file (.cap OR .pcap)', required=True)
    parser.add_argument('input', metavar='FILENAME',
                        help='input file (.cap OR .pcap)')

    parser.add_argument('-n', '--name', metavar="NAME",
                        help='analysis keyword (e.g. Trickbot, Mirai, Zeus, ...)')
    parser.add_argument('-c', '--config', metavar='FILE', default="config/config.yml",
                        help='config file (default: ".config/config.yml")')  # maybe load arguments from the config file too
    parser.add_argument('-a', '--action', metavar="ACTION",
                        help='action to execute [sniffer/...]')

    parser.add_argument(
        '-e', '--enrich', metavar="SERVICE", nargs='?', const="all", help="data enrichment, use comma delimeter and double quotes when selecting more [abuseipdb/securitytrails/virustotal/shodan/all] (default if selected: all)")

    parser.add_argument('-o', '--output', metavar='FILE',
                        help='report output file')

    return parser.parse_args(args=None if sys.argv[1:] else ['--help'])


def init_logger():
    logging_path = f"{os.path.dirname(os.path.realpath(sys.argv[0]))}/logs"
    if not os.path.isdir(logging_path):
        os.mkdir(logging_path)
    logging.basicConfig(format='%(created)f; %(asctime)s; %(levelname)s; %(name)s; %(message)s',
                            filename=f"{logging_path}/c2detective.log", level=logging.DEBUG)  # consider json/yml format for log file
    logger = logging.getLogger('__name__')


def main():
    os.system("clear")
    # print("\033[H\033[J", end="")   # clean screen

    init_logger()
    is_platfrom_supported()

    args = parse_arguments()

    if not args.quiet:
        banner()

    if not args.name is None:
        analysis_name = args.name
        # use analysis name for output/report naming etc.

    if not args.config is None:
        if is_valid_file(args.config, "yml"):
            print(
                f"[{time.strftime('%H:%M:%S')}] [INFO] Loading config '{args.config}' ...")
            logging.info(f"Loading config '{args.config}'")
            config = load_config(args.config)
            analyst_profile = AnalystProfile(config)
            # analyst_profile.print_config()

    input_file = args.input
    if is_valid_file(input_file, "pcap"):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Loading '{input_file}' file ...")
        logging.info(f"Loading '{input_file}' file")
        packet_parser = PacketParser(input_file)

    if not args.enrich is None:
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Data enrichment ...")
        logging.info("Initiating data enrichment engine")
        enrichment_options = args.enrich.split(',')
        # print(enrichment_options)
        enrichment = Enrichment(analyst_profile, packet_parser)
        for service in enrichment_options:
            # TODO: change calling query functions to only enabling the options
            if service == "all":
                enrichment.query_abuseipdb()
                enrichment.query_securitytrails()
                enrichment.query_virustotal()
                enrichment.query_shodan()
                break
            elif service == "abuseipdb":
                enrichment.query_abuseipdb()
            elif service == "securitytrails":
                enrichment.query_securitytrails()
            elif service == "virustotal":
                enrichment.query_virustotal()
            elif service == "shodan":
                enrichment.query_shodan()

    # TODO
    action = args.action
    output_file = args.output

    print(f"\n[{time.strftime('%H:%M:%S')}] [INFO] All done. Exiting program ...\n")


if __name__ == '__main__':
    main()
