import random, struct, socket, sys, time

from src.constants import (
    DNSRecords,
    DNSClasses,
    qtype_from_str, 
    qtype_to_str,
    qclass_from_str,
    qclass_to_str,
)

from src.utils import (
    parse_qname, 
    qname_format
)

class IpAddress:

    def __init__(self, addr, qtype):
        self.addr = addr
        self.qtype = qtype

    def __repr__(self):
        addr_type = "IPv4" if self.qtype == DNSRecords.A_RECORD else "IPv6"
        return f"IpAddress(addr={self.addr}, type={addr_type})"

    def __str__(self):
        match self.qtype:
            case DNSRecords.A_RECORD:
                return socket.inet_ntop(socket.AF_INET, self.addr)
            case DNSRecords.AAAA_RECORD:
                return socket.inet_ntop(socket.AF_INET6, self.addr)
            case DNSRecords.CNAME_RECORD:
                return self.addr

    def set_addr(self, addr, qtype):
        self.addr = addr
        self.qtype = qtype

class DNSQuestion:

    def __init__(self, domain, qtype, qclass):
        self.qname = qname_format(domain)
        self.domain = domain
        self.qtype = qtype
        self.qclass = qclass

    def __repr__(self):
        qtype = qtype_to_str(self.qtype)
        qclass = qclass_to_str(self.qclass) 
        return f"DNSQuestion(qname={self.domain}, qtype={qtype}, qclass={qclass})"

    def __bytes__(self):
        packet = self.qname
        packet += struct.pack(">HH",
            self.qtype,
            self.qclass,
        )

        return packet

class DNSAnswer:

    def __init__(self, address, name, qtype, qclass, ttl):
        self.ip = IpAddress(address, qtype)
        self.name = name
        self.qtype = qtype
        self.qclass = qclass
        self.ttl = ttl

    def __repr__(self):
        qtype = qtype_to_str(self.qtype)
        qclass = qclass_to_str(self.qclass) 
        return f"DNSAnswer(addr={self.ip}, qtype={qtype}, qclass={qclass})"

    def __bytes__(self):
        ...

    @property
    def addr(self):
        return str(self.ip)

class DNSARAnswer:

    def __init__(self, ns, name, qtype, qclass, ttl):
        self.ns = ns
        self.name = name
        self.qtype = qtype
        self.qclass = qclass
        self.ttl = ttl

    def __repr__(self):
        qtype = qtype_to_str(self.qtype)
        qclass = qclass_to_str(self.qclass) 
        return f"DNSARAnswer(ns={self.ns}, qtype={qtype}, qclass={qclass})"

    def __bytes__(self):
        ...

class DNSResponse:

    def __init__(self, domain,
        dns_id,
        flags,
        answers,
        qds,
        ans,
        ars,
        questions,
        qdcount,
        ancount,
        arcount):

        self.domain = domain

        self.id = dns_id
        self.flags = flags
        self.answers = answers
        self.qds = qds
        self.ans = ans
        self.ars = ars
        self.questions = questions
        self.qdcount = qdcount
        self.ancount = ancount
        self.arcount = arcount

    def __repr__(self):
        return f"DNSResponse(questions={self.questions}, qdcount={self.qdcount}, ancount={self.ancount}, arcount={self.arcount})"

    @classmethod
    def from_buffer(cls, domain, buffer):
        dns_id, flags, questions, qdcount, ancount, arcount = struct.unpack('>HHHHHH', buffer[:12])

        buffer_pos = 12

        qds, pos = DNSResponse.parse_questions(
            total=buffer,
            buffer=buffer[buffer_pos:], 
            questions=questions
        )
        buffer_pos += pos

        answers, pos = DNSResponse.parse_answers(
            total=buffer,
            buffer=buffer[buffer_pos:],
            qdcount=qdcount
        )
        buffer_pos += pos

        ans, pos = DNSResponse.parse_authorities(
            total=buffer,
            buffer=buffer[buffer_pos:],
            ancount=ancount
        )
        buffer_pos += pos

        ars, pos = DNSResponse.parse_additionals(
            total=buffer,
            buffer=buffer[buffer_pos:],
            arcount=arcount
        )
        buffer_pos += pos

        return cls(
            domain=domain, 
            dns_id=dns_id,
            answers=answers,
            flags=flags, 
            qds=qds, 
            ans=ans, 
            ars=ars, 
            questions=questions, 
            qdcount=qdcount, 
            ancount=ancount, 
            arcount=arcount
        )

    @staticmethod
    def parse_questions(total, buffer, questions):
        buffer_len = 0
        qnames = []

        for i in range(questions):
            domain, pos = parse_qname(
                total=total, 
                buffer=buffer[buffer_len:]
            )
            buffer_len += pos

            qtype, qclass = struct.unpack('>HH', buffer[buffer_len:buffer_len + 4])
            buffer_len += 4

            question = DNSQuestion(
                domain=domain,
                qtype=qtype,
                qclass=qclass
            )

            qnames.append(question)

        return qnames, buffer_len

    @staticmethod
    def parse_answers(total, buffer, qdcount):
        address = 0
        buffer_len = 0
        ans = []

        for i in range(qdcount):
            an, pos = DNSResponse.parse_answer(
                total=total, 
                buffer=buffer[buffer_len:]
            )
            buffer_len += pos

            ans.append(an)

        DNSResponse.resolve_cnames(ans)

        return ans, buffer_len

    @staticmethod
    def parse_answer(total, buffer):
        buffer_len = 0

        name, pos = parse_qname(
            total=total, 
            buffer=buffer[buffer_len:]
        )
        buffer_len += pos

        qtype, qclass, ttl, data_len = struct.unpack('>HHIH', buffer[buffer_len: buffer_len + 10])
        buffer_len += 10

        # if we want to parse a cname we do it differently
        if qtype == DNSRecords.CNAME_RECORD:
            address, pos = parse_qname(
                total=total, 
                buffer=buffer[buffer_len:]
            )

            buffer_len += data_len
        else:
            address = buffer[buffer_len:buffer_len + data_len]
            buffer_len += data_len

        an = DNSAnswer(
            address=address,
            name=name,
            qtype=qtype,
            qclass=qclass,
            ttl=ttl,
        )

        return an, buffer_len

    @staticmethod
    def parse_authorities(total, buffer, ancount):
        buffer_len = 0
        ans = []

        for i in range(ancount):
            name, pos = parse_qname(
                total=total, 
                buffer=buffer[buffer_len:]
            )
            buffer_len += pos

            qtype, qclass, ttl, data_len = struct.unpack('>HHIH', buffer[buffer_len: buffer_len + 10])
            buffer_len += 10

            nameserver, pos = parse_qname(total, buffer[buffer_len:buffer_len + data_len])
            buffer_len += data_len

            an = DNSARAnswer(
                ns=nameserver,
                name=name,
                qtype=qtype,
                qclass=qclass,
                ttl=ttl,
            )

            ans.append(an)

        return ans, buffer_len

    @staticmethod
    def parse_additionals(total, buffer, arcount):
        buffer_len = 0
        ans = []

        for i in range(arcount):
            name, pos = parse_qname(
                total=total, 
                buffer=buffer[buffer_len:]
            )
            buffer_len += pos

            qtype, qclass, ttl, data_len = struct.unpack('>HHIH', buffer[buffer_len: buffer_len + 10])
            buffer_len += 10

            address = buffer[buffer_len:buffer_len + data_len]
            buffer_len += data_len

            an = DNSAnswer(
                address=address,
                name=name,
                qtype=qtype,
                qclass=qclass,
                ttl=ttl,
            )

            ans.append(an)

        return ans, buffer_len

    @staticmethod
    def resolve_cnames(ans):

        # resolve all cnames
        for an in ans:
            if an.qtype == DNSRecords.CNAME_RECORD:
                cname = str(an.ip)

                # find the address and set it
                for cname_an in ans:
                    if cname_an.name == cname:
                        an.ip.set_addr(cname_an.ip.addr, cname_an.qtype)

class DNSFlags:

    def __init__(self, aa, op, tc, rd, rsv, ad):
        self.aa = aa # Authoriative answer
        self.op = op # Opcode
        self.tc = tc # Truncated response
        self.rd = rd # Recursion desired
        self.rsv = rsv # Reserved
        self.ad = ad # Authentic data

        self.flags = 0

        self.set_bit(self.aa, 5)
        self.set_bit(self.op, 6)
        self.set_bit(self.tc, 7)
        self.set_bit(self.rd, 8)
        self.set_bit(self.rsv, 9)
        self.set_bit(self.ad, 10)

    def __repr__(self):
        return f"DNSFlags(flags={self.flags})"

    def __bytes__(self):
        return bytes(self.flags)

    def __int__(self):
        return self.flags

    def set_bit(self, value, bit):
        self.flags |= (value << bit)

class DNSQuery:

    def __init__(self,
        domains,
        flags,
        qtype=DNSRecords.A_RECORD,
        qclass=DNSClasses.IN_CLASS,
        transaction_id=None, 
        questions=1, 
        qdcount=0, 
        ancount=0, 
        arcount=0):

        if transaction_id is None:
            self.id = random.randint(0, 0xffff)
        else:
            self.id = ta

        self.flags = flags
        self.questions = questions
        self.qdcount = qdcount # Answer count
        self.ancount = ancount # Authority count
        self.arcount = arcount # Additional information count
        self.domains = domains

        self.qtype = qtype
        self.qclass = qclass

    def __bytes__(self):
        packet = struct.pack('>HHHHHH', 
            self.id, 
            self.flags,
            self.questions,
            self.qdcount,
            self.ancount,
            self.arcount,
        )

        for domain in self.domains:
            question = DNSQuestion(
                domain=domain, 
                qtype=self.qtype, 
                qclass=self.qclass
            )
            packet += bytes(question)

        return packet
