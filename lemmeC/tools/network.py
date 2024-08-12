import dns.resolver as res

def get_addresses(domain):
    addresses = []
    print(f"[+](Adresses:Active) Getting addresses for {domain}")
    answer = res.resolve(domain)
    for val in answer:
        addresses.append(val.to_text())
    return addresses
