#!/usr/bin/python3
import os
import sys
import yaml
import requests
import argparse
import datetime

from lemmeC.tools.shodanapi import ShodanApi
from lemmeC.tools.subdomains import get_subdomains 
from lemmeC.tools.network import get_addresses, internetdb

from lemmeC.utils.banner import banner
from lemmeC.utils.utilities import Checks, Filesystem

SHODAN_API_KEY = None

class DomainLookup:
    def __init__(self):
        self.get_request = requests.get
        self.report_time = datetime.datetime.now()
        self.lemme_see_results = {}

    def lookup(self, options):
        self.target = options["target"] # TODO: add check for valid domain
        print(f"[+] Lemme see Domain lookup on target: {self.target}")

        shodan = ShodanApi(SHODAN_API_KEY)
        shodan_results = shodan.getDomainInfo(self.target)

        self.lemme_see_results = {"target":self.target,"time": self.report_time.strftime("%c")}

        ####################### SHODAN #######################
        self.lemme_see_results["os"] = shodan_results["os"]
        self.lemme_see_results["ports"] = shodan_results["ports"]
        self.lemme_see_results["domains"] = shodan_results["domains"]
        self.lemme_see_results["products"] = shodan_results["products"]
        self.lemme_see_results["hostnames"] = shodan_results["hostnames"]
        self.lemme_see_results["addresses"] = shodan_results["addresses"]

        ####################### MISC #######################
        self.lemme_see_results["addresses"] += get_addresses(self.target)
        self.lemme_see_results["subdomains"] = get_subdomains(self.target, self.get_request, SHODAN_API_KEY)
        self.lemme_see_results["subdomain_count"] = str(len(self.lemme_see_results["subdomains"]))
    
        return self.lemme_see_results

class IpLookup:

    def __init__(self):
        self.get_request = requests.get
        self.report_time = datetime.datetime.now()
        self.lemme_see_results = {}
    
    def lookup(self, options):
        self.target = options["target"] # TODO: add check for valid IP
        print(f"[+] Lemme see IP lookup on target: {self.target}")

        shodan = ShodanApi(SHODAN_API_KEY)
        shodan_results = shodan.getIpInfo(self.target)

        self.lemme_see_results = {"target":self.target,"time": self.report_time.strftime("%c")}

        ####################### SHODAN #######################
        self.lemme_see_results["os"] = shodan_results["os"]
        self.lemme_see_results["tags"] = shodan_results["tags"]
        self.lemme_see_results["ports"] = shodan_results["ports"]
        self.lemme_see_results["domains"] = shodan_results["domains"]
        self.lemme_see_results["products"] = shodan_results["products"]
        self.lemme_see_results["http_waf"] = shodan_results["http_waf"]
        self.lemme_see_results["http_host"] = shodan_results["http_host"]
        self.lemme_see_results["hostnames"] = shodan_results["hostnames"]
        self.lemme_see_results["http_status"] = shodan_results["http_status"]
        self.lemme_see_results["http_server"] = shodan_results["http_server"]

        return self.lemme_see_results

class WebLookup:
    def __init__(self):
        pass
    
    def lookup(self, options):
        return {"Message": "Comming Soon :)"}

def main(): 
    global SHODAN_API_KEY
    parser = argparse.ArgumentParser()
    subcmd = parser.add_subparsers(required=True)

    lookup_domain = DomainLookup().lookup
    lookup_ip = IpLookup().lookup
    lookup_web= WebLookup().lookup

    # Sub-Command For Domain Lookup
    cmd_domain = subcmd.add_parser("domain")
    cmd_domain.add_argument("-t", "--target", type=str, required=True,
        help="Target domain name to check (e.g. -d targetdomain.site)")
    cmd_domain.add_argument("-r", "--template", type=str,
        help="User specified HTML template (e.g. -t mytemplate.html)")
    cmd_domain.add_argument("-o", "--output", type=str, default="default",
        help="Name or path to save the results (e.g. -o results_for_domain)")
    cmd_domain.set_defaults(func=lookup_domain)

    # Sub-Command For IP Lookup
    cmd_ip = subcmd.add_parser("ip")
    cmd_ip.add_argument("-t", "--target", type=str, required=True,
        help="Target domain name to check (e.g. -d targetdomain.site)")
    cmd_ip.add_argument("-r", "--template", type=str,
        help="User specified HTML template (e.g. -t mytemplate.html)")
    cmd_ip.add_argument("-o", "--output", type=str, default="default",
        help="Name or path to save the results (e.g. -o results_for_domain)")
    cmd_ip.set_defaults(func=lookup_ip)

    # Sub-Command For Web Lookup
    cmd_web = subcmd.add_parser("web")
    cmd_web.add_argument("-t", "--target", type=str, required=True,
        help="Target domain name to check (e.g. -d targetdomain.site)")
    cmd_web.add_argument("-r", "--template", type=str,
        help="User specified HTML template (e.g. -t mytemplate.html)")
    cmd_web.add_argument("-o", "--output", type=str, default="default",
        help="Name or path to save the results (e.g. -o results_for_domain)")
    cmd_web.set_defaults(func=lookup_web)

    print(banner)
    args = parser.parse_args()
    options = vars(args)

    HOME = os.path.expanduser("~")
    YAML = os.path.join(HOME, ".config", "lemme-see", "config.yaml")
    if os.path.isfile(YAML):
        print("[+] Reading from:", YAML)
        config_file = open(YAML)
        SHODAN_API_KEY = yaml.safe_load(config_file)["shodan"][0]
        config_file.close()
    else:
        print("[!] Could not read:", YAML)
        sys.exit()

    tool_results = args.func(options)
    print(tool_results)

if __name__ == "__main__":
    main()
