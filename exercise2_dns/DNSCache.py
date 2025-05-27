import socket
import time
import json
from dnslib import DNSRecord, QTYPE, RR, A, AAAA, NS, PTR


class DNSCache:
    def __init__(self):
        self.domain_to_ip = {}  # Для A и AAAA записей
        self.ip_to_domain = {}  # Для PTR записей
        self.domain_to_ns = {}  # Для NS записей

    def add_record(self, domain, rdata, ttl, record_type):
        if record_type == 'A' or record_type == 'AAAA':
            self.domain_to_ip[domain] = {'data': str(rdata), 'expire_time': time.time() + ttl}
        elif record_type == 'PTR':
            self.ip_to_domain[domain] = {'data': str(rdata), 'expire_time': time.time() + ttl}
        elif record_type == 'NS':
            self.domain_to_ns[domain] = {'data': str(rdata), 'expire_time': time.time() + ttl}

    def cleanup_expired(self):
        current_time = time.time()
        self.domain_to_ip = {k: v for k, v in self.domain_to_ip.items() if v['expire_time'] > current_time}
        self.ip_to_domain = {k: v for k, v in self.ip_to_domain.items() if v['expire_time'] > current_time}
        self.domain_to_ns = {k: v for k, v in self.domain_to_ns.items() if v['expire_time'] > current_time}

    def save_to_disk(self):
        cache_data = {
            'domain_to_ip': self.domain_to_ip,
            'ip_to_domain': self.ip_to_domain,
            'domain_to_ns': self.domain_to_ns,
            'timestamp': time.time()
        }
        with open('dns_cache.json', 'w') as f:
            json.dump(cache_data, f)

    def load_from_disk(self):
        try:
            with open('dns_cache.json', 'r') as f:
                cache_data = json.load(f)
                self.domain_to_ip = cache_data.get('domain_to_ip', {})
                self.ip_to_domain = cache_data.get('ip_to_domain', {})
                self.domain_to_ns = cache_data.get('domain_to_ns', {})

                time_passed = time.time() - cache_data.get('timestamp', time.time())
                for cache in [self.domain_to_ip, self.ip_to_domain, self.domain_to_ns]:
                    for record in cache.values():
                        record['expire_time'] -= time_passed
                self.cleanup_expired()
        except (FileNotFoundError, json.JSONDecodeError):
            pass


def resolve_recursively(query, cache):
    try:
        root_servers = [
            '198.41.0.4', '199.9.14.201', '192.33.4.12',
            '199.7.91.13', '192.203.230.10', '192.5.5.241',
            '192.112.36.4', '198.97.190.53', '192.36.148.17',
            '192.58.128.30', '193.0.14.129', '199.7.83.42',
            '202.12.27.33'
        ]

        for root in root_servers:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(2)
                sock.sendto(query.pack(), (root, 53))
                data, _ = sock.recvfrom(512)
                response = DNSRecord.parse(data)

                for rr in response.rr + response.auth + response.ar:
                    if rr.rtype == QTYPE.A:
                        cache.add_record(str(rr.rname), rr.rdata, rr.ttl, 'A')
                    elif rr.rtype == QTYPE.AAAA:
                        cache.add_record(str(rr.rname), rr.rdata, rr.ttl, 'AAAA')
                    elif rr.rtype == QTYPE.PTR:
                        cache.add_record(str(rr.rname), rr.rdata, rr.ttl, 'PTR')
                    elif rr.rtype == QTYPE.NS:
                        cache.add_record(str(rr.rname), rr.rdata, rr.ttl, 'NS')
                return response
            except (socket.timeout, socket.error):
                continue
    except Exception as e:
        print(f"Recursive resolution failed: {e}")
    return None


def handle_dns_request(data, cache):
    try:
        request = DNSRecord.parse(data)
        query = request.q
        qname = str(query.qname)
        qtype = query.qtype

        if qtype == QTYPE.A or qtype == QTYPE.AAAA:
            cached = cache.domain_to_ip.get(qname)
            if cached and cached['expire_time'] > time.time():
                response = request.reply()
                if qtype == QTYPE.A:
                    response.add_answer(RR(qname, QTYPE.A,
                                           rdata=A(cached['data']),
                                           ttl=int(cached['expire_time'] - time.time())))
                else:
                    response.add_answer(RR(qname, QTYPE.AAAA,
                                           rdata=AAAA(cached['data']),
                                           ttl=int(cached['expire_time'] - time.time())))
                return response.pack()

        elif qtype == QTYPE.PTR:
            cached = cache.ip_to_domain.get(qname)
            if cached and cached['expire_time'] > time.time():
                response = request.reply()
                response.add_answer(RR(qname, QTYPE.PTR,
                                       rdata=PTR(cached['data']),
                                       ttl=int(cached['expire_time'] - time.time())))
                return response.pack()

        response = resolve_recursively(request, cache)
        if response:
            return response.pack()
        else:
            reply = request.reply()
            reply.header.rcode = 2
            return reply.pack()

    except Exception as e:
        print(f"Error handling request: {e}")
        return data


def main():
    cache = DNSCache()
    cache.load_from_disk()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(("0.0.0.0", 53))

    try:
        while True:
            data, addr = server_socket.recvfrom(512)
            response = handle_dns_request(data, cache)
            server_socket.sendto(response, addr)
    except KeyboardInterrupt:
        cache.save_to_disk()
        server_socket.close()


if __name__ == "__DNSCache__":
    main()