import random
import socket

from src.protocol import DNSFlags, DNSQuery, DNSResponse
from src.constants import DNSRecords, DNSClasses, ROOT_SERVERS

class DNSResolver:

    @property
    def root_server(self):
        return random.choice(ROOT_SERVERS)[1]

    def recv_response(self, domain, s):
        buffer = s.recv(4096)
        return DNSResponse.from_buffer(domain, buffer)

    def query(self,
        domain, 
        qtype=DNSRecords.A_RECORD, 
        qclass=DNSClasses.IN_CLASS, 
        resolver=None):

        resolver = resolver if resolver else self.root_server

        flags = DNSFlags(
            aa=0,
            op=0,
            tc=0,
            rd=1,
            rsv=0,
            ad=0,
        )

        query = DNSQuery(
            domains=[domain],
            flags=int(flags),
            qtype=qtype,
            qclass=qclass,
        )

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.connect((resolver, 53))

        s.send(bytes(query))

        response = self.recv_response(
            domain=domain,  
            s=s
        )

        if not response.answers:
            if response.ancount > 0:
                nameserver = random.choice(response.ans)

                return self.query(
                    domain=domain,
                    qtype=qtype,
                    qclass=qclass,
                    resolver=nameserver.ns
                )

        return response
