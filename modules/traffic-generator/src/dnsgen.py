#!/usr/bin/env python3
"""
Detection-lab DNS traffic generator.

Sends hand-built DNS queries straight to the Route 53 Resolver so that the DNS
detections in this lab have something to fire on. Standard library only: the
lab VPC has no internet path, so nothing can be installed.

Every cycle it produces:
  * a burst of random, high-entropy .com/.net/.info names (classic DGA shape;
    almost all are unregistered, so this is also the NXDOMAIN spike)
  * a burst of word-pair names (dictionary-DGA shape)
  * a burst of TXT lookups with long random labels (DNS tunnelling shape)
  * lookups of public cryptomining-pool hostnames (also expected to raise a
    real GuardDuty CryptoCurrency:EC2/BitcoinTool.B!DNS finding)
  * a .onion lookup (Tor usage indicator)
  * the AWS-published test domains for the DNS Firewall managed lists, which
    resolve to 1.2.3.4 when allowed and get the rule's block response when
    blocked

Nothing here contacts a mining pool or Tor: it only asks the resolver for names.

DNS Firewall Advanced is behavioural and AWS publishes no test domains for it,
so whether this synthetic traffic trips DGA / dictionary-DGA / tunnelling rules
at a given confidence is not guaranteed. LOW confidence gives the best chance.
"""
import random
import socket
import string
import struct
import time

RESOLVER = "169.254.169.253"  # Route 53 Resolver, reachable from any VPC
QTYPES = {"A": 1, "TXT": 16}
CYCLE_SECONDS = 900

# AWS-published canaries for the managed DNS Firewall lists. They resolve to
# 1.2.3.4 unless a rule blocks them. Only the us-east-1 form exists publicly,
# and it is the documented form for testing in every region.
FIREWALL_TEST_DOMAINS = [
    f"controldomain1.{lst}.firewall.route53resolver.us-east-1.amazonaws.com"
    for lst in ("botnetlist", "malwarelist", "aggregatelist")
]

DGA_TLDS = ["com", "net", "info"]

# Small fixed wordlist: dictionary DGAs glue real words together so names look
# legitimate. Some word pairs may be registered domains; the generator only
# resolves them, it never connects.
WORDS = [
    "amber", "anchor", "atlas", "beacon", "breeze", "canyon", "cedar", "comet",
    "coral", "delta", "ember", "falcon", "forest", "galaxy", "harbor", "island",
    "jungle", "lantern", "maple", "meadow", "nebula", "orbit", "pepper", "quartz",
    "raven", "river", "silver", "summit", "thunder", "velvet", "willow", "zenith",
]

MINING_POOL_NAMES = [
    "xmr.nanopool.org",
    "pool.supportxmr.com",
    "gulf.moneroocean.stream",
]


def _label(n: int = 12) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def query(name: str, qtype: str = "A") -> None:
    header = struct.pack(">HHHHHH", random.randint(0, 0xFFFF), 0x0100, 1, 0, 0, 0)
    qname = b"".join(
        bytes([len(part)]) + part.encode() for part in name.rstrip(".").split(".")
    ) + b"\x00"
    packet = header + qname + struct.pack(">HH", QTYPES[qtype], 1)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)
    try:
        sock.sendto(packet, (RESOLVER, 53))
        sock.recv(512)
    except OSError:
        pass  # timeouts are fine; the query is logged either way
    finally:
        sock.close()


def cycle() -> None:
    for _ in range(80):
        query(f"{_label(random.randint(12, 18))}.{random.choice(DGA_TLDS)}")
    for _ in range(40):
        a, b, c = random.sample(WORDS, 3)
        query(f"{a}{b}{c}.com")
    for _ in range(150):
        query(f"{_label(40)}.tunnel.detlab.invalid", "TXT")
    for name in MINING_POOL_NAMES:
        query(name)
    query("detlabtest.onion")
    for name in FIREWALL_TEST_DOMAINS:
        query(name)


if __name__ == "__main__":
    while True:
        cycle()
        time.sleep(CYCLE_SECONDS)
