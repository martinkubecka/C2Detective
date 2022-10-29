import argparse
import sys
import os
import platform
import yaml

from src.analyst_profile import AnalystProfile
from src.packet_parser import PacketParser
from src.data_enrichment import Enrichment


def banner():
    print(r"""
   ____ ____  ____       _            _   _
  / ___|___ \|  _ \  ___| |_ ___  ___| |_(_)_   _____
 | |     __) | | | |/ _ \ __/ _ \/ __| __| \ \ / / _ \
 | |___ / __/| |_| |  __/ ||  __/ (__| |_| |\ V /  __/
  \____|_____|____/ \___|\__\___|\___|\__|_| \_/ \___|

                                    by Martin Kubecka
 -----------------------------------------------------
    """)


def is_platfrom_supported():
    machine_platfrom = platform.system().lower()
    if not machine_platfrom.startswith('linux'):
        print("\n[!] Unsupported platform.")
        print("\nExiting program ...\n")
        exit(1)


def is_valid_file(filename):
    if not os.path.exists(filename):
        print(f"[!] Provided file '{filename}' does not exist.")
        print("\nExiting program ...\n")
        exit(1)
        # add file type checks for txt,xls,xlsx, etc.
    return True


def is_pcap_file(filename):
    if not os.path.exists(filename):
        print(f"[!] Provided file '{filename}' does not exist.")
        print("\nExiting program ...\n")
        exit(1)
    else:
        if not filename.endswith(".pcap") or filename.endswith(".cap"):
            print(f"[!] Provided file '{filename}' is not a pcap/cap file.")
            print("\nExiting program ...\n")
            exit(1)
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
        '-e', '--enrich', help="data enrichment", action='store_true')
    parser.add_argument('-o', '--output', metavar='FILE',
                        help='report output file')

    return parser, parser.parse_args(args=None if sys.argv[1:] else ['--help'])


def main():
    is_platfrom_supported()

    parser, args = parse_arguments()

    # if len(sys.argv) == 1:
    #     # print(f"\n[!] No arguments provided")
    #     parser.print_help("[!] No arguments provided")
    #     exit(1)

    os.system("clear")
    # print("\033[H\033[J", end="")   # clean screen

    if not args.quiet:
        banner()

    if not args.name is None:
        analysis_name = args.name
        # use analysis name for output/report naming etc.

    if not args.config is None:
        if is_valid_file(args.config):
            print(f"\n[*] Loading config '{args.config}' ...")
            config = load_config(args.config)
            analyst_profile = AnalystProfile(config)
            # analyst_profile.print_config()

    input_file = args.input
    if is_valid_file(input_file):
        if is_pcap_file(input_file):
            print(f"\n[*] Loading '{input_file}' file ...")
            packet_parser = PacketParser(input_file)

    if args.enrich:
        print(f"\n[*] Data enrichment ...")
        # data enrichment
        enrichment = Enrichment(analyst_profile, packet_parser)
        # enrichment.query_abuseipdb(packet_parser.external_dst_addresses)

    # TODO
    action = args.action
    output_file = args.output


if __name__ == '__main__':
    main()
