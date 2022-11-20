import argparse
import sys
import os
import platform
import yaml
import logging
import time

from src.analyst_profile import AnalystProfile
from src.packet_parser import PacketParser
from src.enrichment_engine import EnrichmentEngine


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
            if not (filename.endswith(".pcap") or filename.endswith(".cap") or filename.endswith(".pcapng")):
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
    parser.add_argument('-e', '--enrich', metavar="SERVICES", nargs='?', const="all",
                        help="data enrichment, use comma as a delimeter and double quotes when selecting more [abuseipdb/alienvault/bgpranking/securitytrails/shodan/threatfox/virustotal/all] (default if selected: all)")
    parser.add_argument('-o', '--output', metavar='PATH', default="reports",
                        help='output directory file path for report files (default: reports/)')

    return parser.parse_args(args=None if sys.argv[1:] else ['--help'])


def init_logger():
    logging_path = f"{os.path.dirname(os.path.realpath(sys.argv[0]))}/logs"
    if not os.path.isdir(logging_path):
        os.mkdir(logging_path)
    logging.basicConfig(format='%(created)f; %(asctime)s; %(levelname)s; %(name)s; %(message)s',
                        filename=f"{logging_path}/c2detective.log",
                        level=logging.DEBUG)  # consider json/yml format for log file
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
        # packet_parser = None    # TESTING ENRICHMENT

    output_dir = args.output

    if not args.enrich is None:
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Initiating data enrichment engine ...")
        logging.info("Initiating data enrichment engine")
        enrichment_options = args.enrich.split(',')

        enrichment_services = {
            "abuseipdb": False,
            "threatfox": False,
            "securitytrails": False,
            "virustotal": False,
            "shodan": False,
            "alienvault": False,
            "bgp_ranking": False
        }

        for service in enrichment_options:
            if service == "all":
                enrichment_services.update((key, True)
                                           for key in enrichment_services)
                # enrichment.query_abuseipdb()
                # enrichment.query_securitytrails()
                # enrichment.query_virustotal()
                # enrichment.query_shodan()
                # enrichment.query_alienvault()
                # enrichment.query_bgp_ranking()
                # ----------------- TESTING -----------------
                # enrichment.query_abuseipdb("147.175.111.17")
                # enrichment.query_securitytrails("securitytrails.com")
                # enrichment.query_virustotal("027.ru")
                # enrichment.query_shodan("mail.elf.stuba.sk")
                # enrichment.query_alienvault("13.107.21.200")
                # enrichment.query_alienvault("2620:7:6001:0:0:ffff:c759:e653")
                # enrichment.query_alienvault("027.ru")
                # enrichment.query_bgp_ranking("5577", "2019-05-19")
                break
            if service == "abuseipdb":
                enrichment_services.update({"abuseipdb": True})
            if service == "threatfox":
                enrichment_services.update({"threatfox": True})
            if service == "securitytrails":
                enrichment_services.update({"securitytrails": True})
            if service == "virustotal":
                enrichment_services.update({"virustotal": True})
            if service == "shodan":
                enrichment_services.update({"shodan": True})
            if service == "alienvault":
                enrichment_services.update({"alienvault": True})
            if service == "bgpranking":
                enrichment_services.update({"bgp_ranking": True})

        enrichment = EnrichmentEngine(analyst_profile, output_dir, packet_parser, enrichment_services)
        
        # ----------------- TESTING -----------------
        # enrichment.enrich_data("139.180.203.104")   # Cobalt Strike
        # enrichment.enrich_data("147.175.111.17")  # STU - open ports and a lot of vulns
        enrichment.enrich_data("23.105.223.5")  # lot of abuse
        # enrichment.enrich_data("027.ru")
        # enrichment.enrich_data("5577")    # ASN for bgp ranking


    # TODO
    action = args.action

    print(f"\n[{time.strftime('%H:%M:%S')}] [INFO] All done. Exiting program ...\n")


if __name__ == '__main__':
    main()
