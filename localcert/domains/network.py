import dns.resolver
import dns.nameserver

ext_resolver = dns.resolver.Resolver()
ext_resolver.nameservers = ["8.8.8.8", "8.8.4.4", "1.1.1.1"]


def dns_query_A(domain: str) -> list[str]:
    results = ext_resolver.query(domain, "A")
    answers = set([])
    for rdata in results:
        answers.add(rdata.address)
    return list(answers)


def dns_query_TXT(domain: str) -> list[str]:
    results = ext_resolver.query(domain, "TXT")
    answers = set([])
    for rdata in results:
        for s in rdata.strings:
            answers.add(s)
    return list(answers)
