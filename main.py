import random
import requests

from src.resolver import DNSResolver

def resolve_domain(domain):
    dns = DNSResolver()

    r = dns.query(domain)
    answers = r.answers

    result = random.choice(answers)
    return result.ip

r = resolve_domain("google.com")
print(r)
