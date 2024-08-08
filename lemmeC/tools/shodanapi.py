import shodan
import json
import yaml
import sys
import os

class ShodanApi:

    def __init__(self, ApiKey):
        self.api = shodan.Shodan(ApiKey)
        try:
            print(f"[+] Checking Shodan connection")
            info = self.api.info()
        except shodan.APIError as e:
            print(f"[!] Error: {e}")
            sys.exit()

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
    
    def getIpInfo(self, target):
        # Add check for valid IP
        print(f"[+] Quering shodan for IP information")
        api_results = self.api.host(target)
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

    def getDomainInfo(self, target):
        print(f"[+] Quering shodan for domain information")
        api_results = self.api.search(f"hostname:{target}")["matches"]
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

    def getSubdomains(self, target):
        print(f"[+] Getting subdomains from: Shodan")
        api_results = self.api.dns.domain_info(target)
        self.s_subdomains.update(api_results["subdomains"])
        return list(self.s_subdomains)