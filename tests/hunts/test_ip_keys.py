#!/usr/bin/env python3
"""
Property tests for the shared IP SQL (modules/threat-hunting/sql/): the
canonical 32-hex address key and CIDR -> [lo, hi] ranges, for IPv4 and IPv6.

Thousands of random addresses and networks are run through the SQL (Athena
dialect, transpiled to DuckDB) and compared with Python's ipaddress module.
Everything the intel and network hunts conclude about IPs rests on this.

    python3 tests/hunts/test_ip_keys.py
"""
import ipaddress
import pathlib
import random
import sys
import traceback

import duckdb
import sqlglot

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import test_hunts as th  # noqa: E402  (renderer and paths)

SQL = th.MODULE / "sql"
RND = random.Random(20261008)


def ip_key_sql():
    return (SQL / "ip_key.sql").read_text().strip()


def ranges_sql(src, dst):
    return th._fill((SQL / "cidr_ranges.sql.tftpl").read_text(), {"src": src, "dst": dst, "ip_key": ip_key_sql()})


def py_key(text):
    ip = ipaddress.ip_address(text)
    if ip.version == 4:
        ip = ipaddress.IPv6Address("::ffff:" + str(ip))
    return ip.exploded.replace(":", "")


def run(sql, rows, cols):
    con = duckdb.connect()
    con.execute(f"CREATE TABLE inp ({', '.join(c + ' VARCHAR' for c in cols)})")
    con.executemany(f"INSERT INTO inp VALUES ({', '.join('?' for _ in cols)})", rows)
    return con.execute(sqlglot.transpile(sql, read="athena", write="duckdb")[0]).fetchall()


def keys_for(texts):
    sql = f"SELECT v, {ip_key_sql().replace('IP_IN', 'v')} AS k FROM inp"
    return dict(run(sql, [(t,) for t in texts], ["v"]))


def rand_v4():
    return str(ipaddress.IPv4Address(RND.getrandbits(32)))


def rand_v6():
    # Bias towards zero runs so "::" compression appears in many positions.
    groups = [0 if RND.random() < 0.4 else RND.getrandbits(16) for _ in range(8)]
    return ipaddress.IPv6Address(sum(g << (16 * (7 - i)) for i, g in enumerate(groups)))


# --- Tests ---------------------------------------------------------------------------

def test_keys_match_python_for_every_textual_form():
    texts = {"0.0.0.0", "255.255.255.255", "::", "::1", "1::", "fe80::", "2001:db8::1",
             "1:2:3:4:5:6:7::", "::1:2:3:4:5:6:7", "0:0:0:0:0:0:0:0"}
    for _ in range(1500):
        texts.add(rand_v4())
        a = rand_v6()
        texts.update({a.compressed, a.exploded, a.compressed.upper(),
                      ":".join(g.lstrip("0") or "0" for g in a.exploded.split(":"))})   # no leading zeros
    got = keys_for(sorted(texts))
    wrong = {t: (got[t], py_key(t)) for t in texts if got[t] != py_key(t)}
    assert not wrong, list(wrong.items())[:5]
    assert len(texts) > 5000, len(texts)


def test_malformed_input_yields_null_not_a_wrong_key():
    invalid = ["", "abc", "1.2.3", "256.1.1.1", "01.2.3.4", "1.2.3.4.5", "1:2:3:4:5:6:7:8:9",
               "1:2:3:4:5:6:7", "1::2::3", ":::", "12345::", "g::1", "1:2:3:4:5:6:7:8::",
               "::1:2:3:4:5:6:7:8", "s3.amazonaws.com", "AWS Internal"]
    for b in invalid:                     # Python agrees each is invalid
        try:
            ipaddress.ip_address(b)
            raise AssertionError(f"{b!r} is valid in Python; move it to 'unsupported'")
        except ValueError:
            pass
    # Valid notations no AWS log source writes; deliberately unsupported. They
    # must give NULL (no match), never a wrong key.
    unsupported = ["::ffff:1.2.3.4", "64:ff9b::192.0.2.1", "fe80::1%eth0"]
    for u in unsupported:
        ipaddress.ip_address(u)
    got = keys_for(invalid + unsupported)
    assert all(got[b] is None for b in invalid + unsupported), {b: got[b] for b in got if got[b] is not None}


def test_ranges_match_python_network_bounds():
    nets = []
    for _ in range(1500):
        nets.append(ipaddress.ip_network(f"{rand_v4()}/{RND.randint(0, 32)}", strict=False))
        nets.append(ipaddress.ip_network(f"{rand_v6()}/{RND.randint(0, 128)}", strict=False))
    # Feed some with a misaligned base address, as a curator might write them.
    texts = [f"{n.network_address + (RND.randint(0, n.num_addresses - 1) if n.num_addresses > 1 else 0)}/{n.prefixlen}"
             for n in nets]
    texts += ["192.0.2.66", "2001:db8::66"]              # bare addresses: a /32 or /128
    sql = f"WITH {ranges_sql('inp', 'r')} SELECT cidr_text, lo, hi FROM r"
    got = {t: (lo, hi) for t, lo, hi in run(sql, [(t,) for t in texts], ["cidr_text"])}
    wrong = []
    for t in texts:
        n = ipaddress.ip_network(t, strict=False)
        want = (py_key(str(n.network_address)), py_key(str(n.broadcast_address)))
        if got.get(t) != want:
            wrong.append((t, got.get(t), want))
    assert not wrong, wrong[:5]


def test_membership_matches_python():
    pairs = []
    for _ in range(3000):
        if RND.random() < 0.5:
            net = ipaddress.ip_network(f"{rand_v4()}/{RND.randint(8, 32)}", strict=False)
            inside = net.network_address + RND.randint(0, net.num_addresses - 1)
            addr = inside if RND.random() < 0.5 else ipaddress.IPv4Address(RND.getrandbits(32))
        else:
            net = ipaddress.ip_network(f"{rand_v6()}/{RND.randint(16, 128)}", strict=False)
            inside = net.network_address + RND.randint(0, net.num_addresses - 1)
            addr = inside if RND.random() < 0.5 else rand_v6()
        for edge in (net.network_address, net.broadcast_address, net.broadcast_address + 1 if
                     int(net.broadcast_address) < (2 ** net.max_prefixlen - 1) else net.network_address):
            pairs.append((str(net), str(edge)))
        pairs.append((str(net), str(addr)))
    sql = (f"WITH {ranges_sql('inp', 'r')} SELECT cidr_text, a, "
           f"{ip_key_sql().replace('IP_IN', 'a')} BETWEEN lo AND hi AS hit FROM r")
    got = run(sql, pairs, ["cidr_text", "a"])
    wrong = [(n, a, h) for n, a, h in got if h != (ipaddress.ip_address(a) in ipaddress.ip_network(n))]
    assert not wrong and len(got) == len(pairs), wrong[:5]


def test_ipv4_never_matches_ipv6_ranges_used_in_practice():
    """Keys put IPv4 at ::ffff:0:0/96, so IPv6 ranges a curator can add (/32 or
    narrower, validated) never contain IPv4 addresses, and vice versa."""
    sql = (f"WITH {ranges_sql('inp', 'r')} SELECT cidr_text, a, "
           f"{ip_key_sql().replace('IP_IN', 'a')} BETWEEN lo AND hi AS hit FROM r")
    rows = [("2001:db8::/32", "32.1.13.184"), ("198.51.100.0/24", "2001:db8::c633:6400"),
            ("fc00::/7", "10.0.0.1"), ("10.0.0.0/8", "fc00::a00:1")]
    assert [h for *_, h in run(sql, rows, ["cidr_text", "a"])] == [False] * 4


if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"PASS  {name}")
        except Exception:  # noqa: BLE001
            failed += 1
            print(f"FAIL  {name}\n{traceback.format_exc()[-1500:]}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
