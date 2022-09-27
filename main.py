import argparse
import sys
import os


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


def is_valid_file(file):
    if not os.path.exists(file):
        print(f"[!] Provided file '{file}' does not exist.")
        exit(1)
    # else:
    #     return open(arg, 'r')  # return an open file handle


def parse_arguments():
    parser = argparse.ArgumentParser(prog='c2detective',
                                     description='Application for detecting command and control (C2) '
                                                 'communication through network traffic analysis.')

    parser.add_argument('-q', '--quiet', help="don't print the banner and other noise", action='store_true')
    parser.add_argument('-i', help='input file (.cap OR .pcap)', metavar='FILE', required=True,
                        type=lambda file: is_valid_file(file))

    return parser.parse_args()


def main():
    args = parse_arguments()
    # interactive mode : sys.argv[0] == main.py
    if len(sys.argv) == 1:
        print("interactive mode")
        banner()
    # command line mode
    else:
        print("command line mode")
        if not args.quiet:
            banner()
        if args.input:
            print("input set")


if __name__ == '__main__':
    main()
