"""

Note: Scapy does not use the TCP implementation made available by the Kernel.

This has implications for the way you deal with the TCP handshake.
- Scapy sends out its own SYN (unbeknownst to your kernel)
- The Kernel and Scapy receives the SYN/ACK. This is unexpected to the kernel
    so it sends a TCP RST and shuts down the connection (making it unusable
    for Scapy).

To circumvent this problem, you should have TCP RST packets from your kernel
blocked. This means the outgoing RST from your kernel to the server gets dropped
by the kernel "firewall" ==> the connection stays open for scapy to use.

Run:
`sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -s <your IP from 'ifconfig'> -j DROP`
in the command line of your Linux VM.
"""


from scapy.all import *
from scapy.layers.inet import TCP, IP
from scapy.layers.http import HTTP, HTTPRequest

import random


class HTTPProber:
    """
    This class contains methods required to complete a TCP handshake with a specific
    web server, send a HTTP GET request to that server with a specific user-agent in
    the HTTP headers, and save the content returned by the web server.
    """

    def __init__(self, dst_ip,  dst_port, src_port, user_agent):
        self.dst_ip, self.dst_port = dst_ip, dst_port
        self.src_port = src_port
        self.user_agent = user_agent
        self.content = []
        self.seq = 0
        self.ack = 0
        self.__start_connection()
        self.__send_get_request()
        self.__end_connection()

    def __start_connection(self):
        """
        This method will complete a 3-way TCP handshake with the
        <self.dst_ip,self.dst_port> server.

        1. You will need to craft a TCP packet to the server which has the SYN flag set
            and contains an appropriate sequence number and source port. Once you have
            this packet you will find an appropriate Scapy function to send this packet
            and record the server's response (the SYN/ACK).

        2. You will then need to parse the server's response to extract its sequence number
            and use this to set the acknowledgment number in your ACK packet. Send your ACK
            back to the server with the ACK flag set and the appropriate sequence and
            acknowledgement numbers.

        The 3-way handshake is now complete.

        :return:
        """
        SYN_flag = TCP(sport=self.src_port, dport=self.dst_port, seq=1, flags="S") 
        SYN_ACK = sr1(IP(dst=self.dst_ip)/SYN_flag)

        # print(SYN_ACK[TCP].seq)
        # print(SYN_ACK[TCP].ack)

        self.seq =  SYN_ACK[TCP].ack + 1
        self.ack = SYN_ACK[TCP].seq + 1

        ACK_packet = TCP(sport=self.src_port, dport=self.dst_port, seq=self.seq, ack=self.ack, flags="A")
        # print(ACK_packet[TCP].seq)
        # print(ACK_packet[TCP].ack)

        send(IP(dst=self.dst_ip)/ACK_packet)
        #print(SYN_ACK[TCP].seq)

        return True


    def __send_get_request(self):
        """
        This method will construct, send, and record the responses from a HTTP GET request
        to the specific web server.

        1. Construct a HTTP GET request packet to the server. When doing so, be sure to:
            - set the IP addresses and TCP ports (source and destination correctly).
            - set the appropriate TCP sequence and acknowledgement numbers.
            - set the HTTPRequest user agent to the value in `self.user_agent`.
            - other parameters to be set in the HTTP request are:
                                                           Host=self.dst_ip+":"+str(self.dst_port),
                                                           Accept="text/html",
                                                           Accept_Language="en-US,en",
                                                           Connection="close"

        2. Send the constructed GET request and monitor for responses keeping in mind that
            responses may be spread across multiple packets. Save the responses.
            - Remember that you will need to ACK responses as they come in (with the correct ACK numbers).
                Otherwise the sender will keep resending them.

        3. From each response packet make sure to extract the HTTP content and append it to the
            `self.content` list.

        :return:
        """
        responses = []
        # reqStr = 'GET / HTTP/1.1\r\nHost: {}'.format(self.dst_ip)
        http_request_str = 'Get / HTTP/1.1\r\nAccept: text/html\r\nAccept-Language: en-US,en\r\nConnection: close\r\nHost: {}\r\nUser-Agent: knock knock\r\n\r\n'.format(self.dst_ip)

        http_request = HTTPRequest(User_Agent=self.user_agent, Host=self.dst_ip+":"+str(self.dst_port), 
            Accept="text/html", Accept_Language="en-US,en", Connection="close", Method="Get")

        packet = IP(dst=self.dst_ip) / TCP(dport=self.dst_port, sport=self.src_port, 
                    seq=self.seq, flags='A') / HTTP() / http_request_str

        get_request = sr(packet, multi=1, timeout=5)
        #get_request.show()
        answers, unans = get_request
        # answers.show()
        for i in answers:
            #i.show()
            #print(i[1][Padding].load)
            self.content.append(i[1][Padding].load)
            self.seq = i[1][TCP].ack + 1
            self.ack = i[1][TCP].seq + 1
            ACK_packet = TCP(sport=self.src_port, dport=self.dst_port, seq=self.seq, ack=self.ack, flags="A") 
            j = sr1((IP(dst=self.dst_ip)/ACK_packet), timeout=5)

        #print(self.content)

        return True

    def __end_connection(self):
        """
        This method will send a FIN packet and exit.

        1. Construct a TCP FIN packet with the appropriate header values and flags.
        2. Send this packet.
        3. return. [we're not going to be polite].

        :return:
        """
        FIN = TCP(sport=self.src_port, dport=self.dst_port, flags="FA", seq=1)
        send(FIN)
        return True


def main():
    HTTPProber("toutatis.cs.uiowa.edu", 8118, random.choice(range(1024, 2**16-1)), "knock knock")
    # HTTPProber("toutatis.cs.uiowa.edu", 8118, random.choice(range(1024, 2**16-1)), "knock knock")
    # HTTPProber("www.google.com", 80, random.choice(range(1024, 2**16-1)), "knock knock")


if __name__ == '__main__':
    main()
