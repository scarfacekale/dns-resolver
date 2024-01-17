from enum import IntEnum

# DNS Rootservers hints
ROOT_SERVERS = (
    ("a.root-servers.net", "198.41.0.4"),
    ("b.root-servers.net", "199.9.14.201"),
    ("c.root-servers.net", "192.33.4.12"),
    ("d.root-servers.net", "199.7.91.13"),
    ("e.root-servers.net", "192.203.230.10"),
    ("f.root-servers.net", "192.5.5.241"),
    ("g.root-servers.net", "192.112.36.4"),
    ("h.root-servers.net", "198.97.190.53"),
    ("i.root-servers.net", "192.36.148.17"),
    ("j.root-servers.net", "192.58.128.30"),
    ("k.root-servers.net", "193.0.14.129"),
    ("l.root-servers.net", "199.7.83.42"),
    ("m.root-servers.net", "202.12.27.33")
)

class DNSRecords(IntEnum):
    A_RECORD        = 0x01
    NS_RECORD       = 0x02
    CNAME_RECORD    = 0x05
    AAAA_RECORD     = 0x1c

class DNSClasses(IntEnum):
    IN_CLASS        = 0x0001

class DNSIPTypes(IntEnum):
    IPV4_TYPE       = DNSRecords.A_RECORD
    IPV6_TYPE       = DNSRecords.AAAA_RECORD

def qtype_from_str(qtype):
    qtypes = {
        "A": DNSRecords.A_RECORD,
        "AAAA": DNSRecords.AAAA_RECORD,
        "NS": DNSRecords.NS_RECORD,
        "CNAME": DNSRecords.CNAME_RECORD,
    }

    return qtypes.get(qtype)

def qtype_to_str(qtype):
    qtypes = {
        DNSRecords.A_RECORD: "A",
        DNSRecords.AAAA_RECORD: "AAAA",
        DNSRecords.NS_RECORD: "NS",
        DNSRecords.CNAME_RECORD: "CNAME",
    }

    return qtypes.get(qtype)

def qclass_from_str(qclass):
    qclasses = {
        "IN": DNSClasses.IN_CLASS,
    }

    return qclasses.get(qclass)

def qclass_to_str(qclass):
    qclasses = {
        DNSClasses.IN_CLASS: "IN",
    }

    return qclasses.get(qclass)
