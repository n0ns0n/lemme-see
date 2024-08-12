import requests
import shodan
import time
import json
import yaml
import sys
import os

class ShodanApi:

    def __init__(self, api_keys, target):
        #self.api = shodan.Shodan(ApiKey)
        self.target = target
        self.api_keys = api_keys
        self.s_os          = set()
        self.s_tags        = set()
        self.s_ports       = set()
        self.s_domains     = set()
        self.s_products    = set()
        self.s_http_waf    = set()
        self.s_http_host   = set()
        self.s_addresses   = set()
        self.s_hostnames   = set()
        self.s_subdomains  = set()
        self.s_http_status = set()
        self.s_http_server = set()

    def getShodanIdb(self):
        print(f"[+](Shodan:InternetDB) Querying InternetDB for IP information.")
        url = f"https://internetdb.shodan.io/{self.target}"
        idb_results = requests.get(url).json()
        if "detail" not in idb_results:
            self.s_hostnames.update(idb_results["hostnames"])
            self.s_ports.update(idb_results["ports"])
            self.s_tags.update(idb_results["tags"])

            shodan_results = {
                "idb"       : True,
                "tags"      : list(self.s_tags),
                "ports"     : list(self.s_ports),
                "hostnames" : list(self.s_hostnames),
            }
            return shodan_results
        else:
            return idb_results
    
    def getShodan(self, asset):
        current_key = 0
        print(f"[+](Shodan) Checking shodan API access")
        while True:
            try:
                if not self.api_keys or current_key > len(self.api_keys) -1:
                    if asset == "domain" or asset == "subdomains":
                        return False
                    else:
                        return self.getShodanIdb()
                else:
                    self.api = shodan.Shodan(self.api_keys[current_key])
                    info = self.api.info()
                    if asset == "ip":
                        print(f"[+](Shodan) Quering shodan for IP information")
                        return self.getIpInfo()
                    elif asset == "subdomains":
                        print(f"[+] Getting subdomains from: Shodan")
                        return self.getSubdomains()
                    elif asset == "domain":
                        print(f"[+](Shodan) Quering shodan for domain information")
                        return self.getDomainInfo()
            except shodan.APIError as api_error:
                current_key += 1
                time.sleep(1)
                print(f"[!](Shodan) Error: {api_error.value}")

    def getIpInfo(self):
        # Add check for valid IP
        api_results = self.api.host(self.target)
        self.s_tags.update(api_results["tags"])
        self.s_domains.update(api_results["domains"])
        self.s_hostnames.update(api_results["hostnames"])
        for data in api_results["data"]:
            try:
                self.s_products.add(data["product"])
                self.s_http_status.add(data["http"]["status"])
                self.s_http_waf.add(data["http"]["waf"])
                self.s_http_server.add(data["http"]["server"])
                self.s_http_host.add(data["http"]["host"])
                self.s_os.add(data["os"])
                self.s_tags.update(data["tags"])
                self.s_hostnames.update(data["hostnames"])
                self.s_domains.update(data["domains"])
                self.s_ports.add(data["port"])
            except KeyError:
                continue
            
        shodan_results = {
            "os"          : list(self.s_os),
            "tags"        : list(self.s_tags),
            "ports"       : list(self.s_ports),
            "domains"     : list(self.s_domains),
            "products"    : list(self.s_products),
            "http_waf"    : list(self.s_http_waf),
            "http_host"   : list(self.s_http_host),
            "hostnames"   : list(self.s_hostnames),
            "http_status" : list(self.s_http_status),
            "http_server" : list(self.s_http_server)
        }

        return shodan_results

    def getDomainInfo(self):
        api_results = self.api.search(f"hostname:{self.target}")["matches"]
        for match in api_results:
            try:
                self.s_ports.add(match["port"])
                self.s_products.add(match["product"])
                self.s_hostnames.update(match["hostnames"])
                self.s_domains.update(match["domains"])
                self.s_addresses.add(match["ip_str"])
                self.s_os.add(match["os"])
            except KeyError:
                continue

        shodan_results = {
            "os"        : list(self.s_os),
            "ports"     : list(self.s_ports),
            "domains"   : list(self.s_domains),
            "products"  : list(self.s_products),
            "hostnames" : list(self.s_hostnames),
            "addresses" : list(self.s_addresses)
        }

        return shodan_results

    def getSubdomains(self):
        api_results = self.api.dns.domain_info(self.target)
        self.s_subdomains.update(api_results["subdomains"])
        return list(self.s_subdomains)