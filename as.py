import os
import re
import socket
import requests
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


def trace(target):
    try:
        target_ip = socket.gethostbyname(target)
    except:
        print(f"Failed to resolve address {target}")
        return None

    output_file = "trace_temp.txt"

    if os.name == 'nt':
        os.system(f"tracert -d {target} > {output_file}")
    else:
        os.system(f"traceroute -n {target} > {output_file} 2>&1")

    with open(output_file, 'r') as f:
        lines = f.read().splitlines()
    os.remove(output_file)

    found_ips = []
    ip_regex = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

    for line in lines:
        if "Request timed out" in line or "* * *" in line:
            found_ips.append(None)
            continue

        match = ip_regex.search(line)
        if match:
            ip = match.group()
            if ip != target_ip:
                found_ips.append(ip)

    return found_ips if found_ips else None


def get_ip_info(ip):
    if not ip or ip.startswith(('127.', '10.', '192.168.', '172.')):
        return None, None, None

    try:
        ripe_data = requests.get(f"https://stat.ripe.net/data/whois/data.json?resource={ip}", timeout=5)
        if ripe_data.status_code == 200:
            data = ripe_data.json()
            asn = None
            country = None
            provider = None

            for record in data.get('data', {}).get('records', []):
                for attr in record.get('attributes', []):
                    if attr.get('name') == 'origin':
                        asn = attr.get('value')
                    elif attr.get('name') == 'country':
                        country = attr.get('value')
                    elif attr.get('name') == 'descr':
                        provider = attr.get('value') if not provider else provider

            if asn or country or provider:
                return asn, country, provider

        ipapi_data = requests.get(f"http://ip-api.com/json/{ip}?fields=as,country,isp", timeout=5)
        ipapi_data.raise_for_status()
        data = ipapi_data.json()
        return data.get('as'), data.get('country'), data.get('isp')

    except:
        return None, None, None


def main():
    target = input("Enter domain or IP to trace: ").strip()

    print("\nTracing route...")
    ips = trace(target)
    if not ips:
        print("Trace failed")
        return

    print("\nResults:")
    print("№  | IP           | AS        | Country   | Provider")
    print("---------------------------------------------------")

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(get_ip_info, ip): i for i, ip in enumerate(ips) if ip}

        results = [None] * len(ips)
        for future in as_completed(futures):
            idx = futures[future]
            results[idx] = future.result()

    for i, ip in enumerate(ips):
        asn, country, provider = results[i] if ip else (None, None, None)
        print(f"{i + 1:2d} | {ip or '*':12} | {asn or 'N/A':8} | {country or 'N/A':8} | {provider or 'N/A':8}")
        time.sleep(0.1)


if __name__ == "__main__":
    main()
