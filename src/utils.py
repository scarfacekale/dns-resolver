import struct
from src.constants import *

"""
 This will convert 3www6google3com  to www.google.com
"""

def parse_qname(total, buffer):
    pos = 0
    buffer_len = 0
    qname = ""

    while True:
        pos = buffer[buffer_len]

        if pos == 0:
            qname = qname[:len(qname) - 1] # remove the last .
            buffer_len += 1
            break
        elif pos >= 192:
            ptr = struct.unpack(">H", buffer[buffer_len:buffer_len + 2])[0]
            ptr -= 49152

            part, pos = parse_qname(total, total[ptr:])
            buffer_len += 2

            qname += part
            break

        buffer_len += 1

        qname += buffer[buffer_len:buffer_len + pos].decode()
        qname += '.'

        buffer_len += pos

    return qname, buffer_len

"""
 This will convert www.google.com to 3www6google3com 
"""

def qname_format(domain):
    qname = domain.index(".").to_bytes(1, 'big')

    for i, c in enumerate(domain):
        if c == '.':
            try:
                qname += domain[i + 1:].index(".").to_bytes(1, 'big')
            except ValueError:
                qname += len(domain[i + 1:]).to_bytes(1, 'big')
        else:
            qname += bytes(c, 'utf-8')

    # null terminator
    qname += b'\x00'

    return qname
