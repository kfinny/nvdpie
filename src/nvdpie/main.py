from argparse import ArgumentParser, Namespace
import json

from .client import Client


def process_response(response, args: Namespace):
    if args.outfile:
        with open(args.outfile, 'w') as fd:
            json.dump(response, fd, indent=4)
    else:
        print(json.dumps(response, indent=4))


def do_cves(client: Client, args: Namespace):
    response = client.cves(cveId=args.cve)
    process_response(response, args)


def do_cvehistory(client: Client, args: Namespace):
    pass


def do_cpes(client: Client, args: Namespace):
    pass


def do_cpematch(client: Client, args: Namespace):
    pass


def main():
    parser = ArgumentParser('nvdpie')
    parser.add_argument('--outfile', help='Path to output file.')
    parser.add_argument('--apikey', help='API Key')

    subparsers = parser.add_subparsers(description='sub-command help')
    commands = [
        ('cves', do_cves),
        ('cvehistory', do_cvehistory),
        ('cpes', do_cpes),
        ('cpematch', do_cpematch)
    ]

    def create_subparser(name, func):
        help_text = f'A sub-command for the {name} endpoint'
        sp = subparsers.add_parser(name, help=help_text, description=help_text)
        sp.set_defaults(func=func)
        return sp

    all_sub_parsers = dict([(n, create_subparser(n, f)) for n, f in commands])

    # cpes arguments
    all_sub_parsers['cves'].add_argument('--cve', help='The CVE ID to search.')

    args = parser.parse_args()
    client = Client(args.apikey)
    args.func(client, args)
