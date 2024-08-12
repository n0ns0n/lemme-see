#!/usr/bin/python3
import os
import sys
import yaml
import requests
import argparse
import datetime

from lemmeC.tools.shodanapi import ShodanApi
from lemmeC.tools.screenshot import Screenshoter
from lemmeC.tools.subdomains import get_subdomains 
from lemmeC.tools.network import get_addresses, internetdb

from lemmeC.utils.banner import banner
from lemmeC.utils.utilities import Checks, Filesystem

SHODAN_API_KEYS = None
APIFLASH_KEYS = None

class DomainLookup:
    def __init__(self):
        self.get_request = requests.get
        self.report_time = datetime.datetime.now()
        self.lemme_see_results = {}

    def lookup(self, options):
        self.target = options["target"] # TODO: add check for valid domain
        self.lemme_see_results["target"] = self.target
        self.lemme_see_results["time"] = self.report_time.strftime("%c")
        self.lemme_see_results["addresses"] = []
        print(f"[+] Lemme see Domain lookup on target: {self.target}")

        ####################### SHODAN #######################
        shodan = ShodanApi(SHODAN_API_KEYS, self.target)
        shodan_results = shodan.getShodan("domain")
        if shodan_results:
            print("got shodan results")
            self.lemme_see_results["os"] = shodan_results["os"]
            self.lemme_see_results["ports"] = shodan_results["ports"]
            self.lemme_see_results["domains"] = shodan_results["domains"]
            self.lemme_see_results["products"] = shodan_results["products"]
            self.lemme_see_results["hostnames"] = shodan_results["hostnames"]
            self.lemme_see_results["addresses"] = shodan_results["addresses"]

        ####################### MISC #######################
        self.lemme_see_results["addresses"] += get_addresses(self.target)
        self.lemme_see_results["subdomains"] = get_subdomains(self.target, self.get_request, SHODAN_API_KEYS)
        self.lemme_see_results["subdomain_count"] = str(len(self.lemme_see_results["subdomains"]))
    
        return self.lemme_see_results

class IpLookup:

    def __init__(self):
        self.report_time = datetime.datetime.now()
        self.lemme_see_results = {}
    
    def lookup(self, options):
        self.target = options["target"] # TODO: add check for valid IP
        self.lemme_see_results["target"] = self.target
        self.lemme_see_results["time"] = self.report_time.strftime("%c")
        print(f"[+] Lemme see IP lookup on target: {self.target}")

        shodan = ShodanApi(SHODAN_API_KEYS, self.target)
        shodan_results = shodan.getShodan("ip")


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
        self.report_time = datetime.datetime.now()
        self.lemme_see_results = {}
    
    def lookup(self, options):
        self.target = options["target"] # TODO: add check for valid URL
        self.is_active = options["active"]
        self.lemme_see_results["target"] = self.target
        self.lemme_see_results["time"] = self.report_time.strftime("%c")
        print(f"[+] Lemme see Web lookup on target: {self.target}")

        ####################### APIFLASH #######################
        web_screenshot = Screenshoter(self.target, self.is_active, APIFLASH_KEYS)
        screenshot = web_screenshot.take_screenshot()

        self.lemme_see_results["screenshot"] = screenshot

        return self.lemme_see_results


def readConfig():
    global SHODAN_API_KEYS
    global APIFLASH_KEYS
    HOME = os.path.expanduser("~")
    YAML = os.path.join(HOME, ".config", "lemme-see", "config.yaml")
    if os.path.isfile(YAML):
        print("[+] Reading from:", YAML)
        config_file = open(YAML)
        API_KEYS = yaml.safe_load(config_file)
        SHODAN_API_KEYS = API_KEYS["shodan"]
        APIFLASH_KEYS = API_KEYS["apiflash"]
        config_file.close()
    else:
        print("[!] Could not read:", YAML)
        sys.exit()

def main(): 
    parser = argparse.ArgumentParser()
    parser.add_argument("tool", choices=["domain", "ip", "web"],
        help="Choose whether to do a domain, ip or web lookup")
    parser.add_argument("-t", "--target", type=str, required=True,
        help="Target domain name to check (e.g. -d targetdomain.site)")
    parser.add_argument("-r", "--template", type=str,
        help="User specified HTML template (e.g. -t mytemplate.html)")
    parser.add_argument("-o", "--output", type=str, default="default",
        help="Name or path to save the results (e.g. -o results_for_domain)")
    parser.add_argument("-a", "--active", action="store_true", default=False,
        help="Enable active lookups on the target.")

    tools = {
        "ip"     : IpLookup().lookup,
        "web"    : WebLookup().lookup,
        "domain" : DomainLookup().lookup
    }

    print(banner)
    readConfig()
    args = parser.parse_args()
    tool_results = tools[args.tool](vars(args))
    print(tool_results)

if __name__ == "__main__":
    main()
