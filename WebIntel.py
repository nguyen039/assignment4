"""
This class takes a URL and does the following:

- Runs a DNS query for the domain associated with the URL
    using a custom resolver.
- Sends an HTTP GET request for that URL using a custom
    HTTP User-Agent using the IP address from the DNS query.
- Obtains the path between the client and the domain with a
    custom implementation of traceroute.
"""

import DNSProbes
import HTTPProbes
import TraceRouteProbes
import random


class WebIntel:

    def __init__(self, url, port):
        self.dst_url = url
        self.dst_port = port
        self.dns_ips, self.http_content, self.traceroute_path = None, None, None

    def dns_probe(self):
        """
        send a dns request. get response. save parsed response.
        :return:
        """
        dns = DNSProbes.DNSProber(resolver="8.8.8.8", domain=self.dst_url, query_type="A")
        self.dns_ips = dns.returned_ips

    def http_probe(self, user_agent):
        """
        do tcp handshake. send get request with specified user
        agent. save parsed http content. close tcp connection.
        :param user_agent:
        :return:
        """
        http = HTTPProbes.HTTPProber(self.dns_ips[0], self.dst_port, user_agent=user_agent,
                                     src_port=random.choice(range(1024, 2 ** 16 - 1)))
        self.http_content = http.content

    def traceroute_probe(self):
        """
        send icmp echo packets with increasing TTLs. save
        parsed responses.
        :return:
        """
        traceroute = TraceRouteProbes.RouteProber(self.dns_ips[0])
        self.traceroute_path = traceroute.path


def main():
    wi = WebIntel(url="cs.uiowa.edu", port=80)
    wi.dns_probe()
    print(wi.dns_ips)
    wi.http_probe("knock knock")
    print(wi.http_content)
    wi.traceroute_probe()
    print(wi.traceroute_path)


if __name__ == '__main__':
    main()
