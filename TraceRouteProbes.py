from scapy.all import *
from scapy.layers.inet import ICMP, IP


class RouteProber:
    """
    This class contains methods to run a traceroute to a specific IP address.

    A brief description of what you need to do is provided below, but you may
    find it helpful to read more about how traceroute works here:
    https://en.wikipedia.org/wiki/Traceroute#Implementations
    """

    def __init__(self, dst_ip):
        self.dst_ip = dst_ip
        self.path = []
        self.__construct_path()

    def __construct_path(self):
        """
        1. You will construct 20 ICMP packets with the IP destination `self.dst_ip` such that:
            packet `i` has a IP TTL of `i`.

        2. You will send each packet and record the response using the Scapy `sr1` method.

        3. Parse the responses to extract the sender's IP address. Save the IP addresses
        ordered from response packet 1 to response packet 20. This is the path taken to
        reach the specified destination.

        :return:
        """


def main():
    tr = RouteProber("8.8.8.8")
    print(tr.path)


if __name__ == '__main__':
    main()

