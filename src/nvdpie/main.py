from argparse import ArgumentParser
import json

from .client import Client


def main():
    parser = ArgumentParser('nvdpie')
    parser.add_argument('--query', choices=['cves','cpes'])
    parser.add_argument('--cve', help='CVE ID')
    parser.add_argument('--addon', action='store_true', help='Include CPE or CVE information')
    parser.add_argument('--outfile', help='Path to output file.')
    parser.add_argument('--apikey', help='API Key')

    options = parser.parse_args()

    if not (options.query or options.cve):
        parser.print_usage()
        print("Please provide 'query' or 'cve' option")
        return

    client = Client(options.apikey)
    if options.query == 'cves':
        response = client.cves(add_ons=options.addon)
    elif options.query == 'cpes':
        response = client.cpes(add_ons=options.addon)
    else:
        response = client.cve(options.cve, add_ons=options.addon)

    if options.outfile:
        with open(options.outfile, 'w') as fd:
            fd.write(response.json(indent=4))
    else:
        print(response.json(indent=4))
