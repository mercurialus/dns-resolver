# dns_resolver — TTL‑aware LRU‑cached Recursive DNS CLI

A small, educational DNS resolver that sends raw UDP DNS queries, follows CNAMEs, and caches answers using a TTL‑aware Least Recently Used (LRU) cache. Includes tracing, TTL inspection, and simple benchmarking from the command line.

---

##  Features

- **Raw UDP DNS** query/response handling (no external libs)
- **TTL‑aware LRU cache** (unordered_map + doubly‑linked list)
- **CNAME following** with **min‑TTL** across the chain
- **Negative caching** (NXDOMAIN) with a conservative default TTL (60s)
- **CLI tools**:
  - `--type=A|AAAA|MX|CNAME`
  - `--trace` (show cache hit/miss, TTLs, timings)
  - `--show-ttl` (print remaining TTL in cache)
  - `--bench=N` (repeat the query N times and show hit ratio)

>  For simplicity, the resolver uses public recursive resolvers as upstreams (default: `1.1.1.1`, `8.8.8.8`, `9.9.9.9`). You can change them in `resolver.cpp`.

---

##  Build

### Prerequisites
- g++ with C++17 support
- make

### Build with Makefile

```bash
make
```
The binary will be created at:
```
bin/dns_resolver
```

### Clean
```bash
make clean
```

### Manual build (without make)
```bash
g++ src/main.cpp src/resolver.cpp src/dns_packet.cpp src/dns_client.cpp src/dns_utils.cpp -Iinclude -std=c++17 -O2 -Wall -o bin/dns_resolver
```

---

##  Project Layout
```
.
├── include/
│   ├── dns_client.h
│   ├── dns_packet.h
│   ├── dns_utils.h
│   ├── lru_ttl_cache.h
│   └── resolver.h
├── src/
│   ├── dns_client.cpp
│   ├── dns_packet.cpp
│   ├── dns_utils.cpp
│   ├── main.cpp
│   └── resolver.cpp
├── obj/            # built by make
├── bin/            # built by make
└── Makefile
```

---

##  Usage

```bash
./bin/dns_resolver <domain> [--type=A|AAAA|MX|CNAME] [--trace] [--show-ttl] [--bench=N]
```

### Examples

**1) A record (default):**
```bash
./bin/dns_resolver example.com
```

**2) IPv6 with tracing:**
```bash
./bin/dns_resolver example.com --type=AAAA --trace
```
Sample trace output:
```
[MISS] example.com type=AAAA cached_ttl=295s
Resolved example.com (type=AAAA) in 120 ms:
  - 2606:2800:220:1:248:1893:25c8:1946
TTL remaining (approx): 295s
```

**3) Benchmark (repeat 50 runs):**
```bash
./bin/dns_resolver example.com --bench=50 --trace
```
Sample summary:
```
Benchmark: 50 runs in 243 ms
Cache stats: hits=49 misses=1
```

**4) Inspect TTL left in cache:**
```bash
./bin/dns_resolver example.com --show-ttl
```
Sample output:
```
Cache TTL remaining for example.com (type=A): 271s
```

---

## 🔍 How it Works (High‑level)

1. **Packet build**: `dns_packet.cpp` constructs a DNS query with the chosen QTYPE.
2. **UDP send/recv**: `dns_client.cpp` sends the query to the upstream resolver and waits for a response with a timeout.
3. **Parsing**: `dns_packet.cpp` / `resolver.cpp` parse the response, collecting A/AAAA/MX/CNAME answers and each record’s TTL.
4. **CNAME following**: If a CNAME is returned for A/AAAA queries, the resolver repeats the query for the CNAME target. The **effective TTL** becomes the **minimum** along the chain.
5. **TTL‑aware LRU cache**: `lru_ttl_cache.h` stores `(domain|qtype) → answers` with an `expires_at` computed from the TTL. On hit, it moves the entry to MRU; on capacity overflow, it evicts LRU. Expired entries are treated as misses.
6. **Negative caching**: If NXDOMAIN is seen, the resolver caches an empty answer set for **60 seconds** (configurable in code).

---

##  Configuration

- **Upstream resolvers**: change `ROOT_SERVERS` in `resolver.cpp`.
- **Cache capacity**: adjust LRU size in `main.cpp` (`LruTtlCache<..., ...> dns_cache(512);`).
- **Timeouts**: tweak timeout seconds in `recv_response()` (currently `3s`).

---

##  Testing Tips

- Test cache HIT behavior:
  ```bash
  ./bin/dns_resolver example.com --trace
  ./bin/dns_resolver example.com --trace
  ```
- Test CNAME chains (e.g., `www.google.com`).
- Test negative caching:
  ```bash
  ./bin/dns_resolver no-such-domain-xyz-abc-test.com --trace
  ```

---

##  Limitations / TODO

- No TCP fallback for >512B responses / truncation (TC bit)
- No EDNS(0) / DNSSEC
- Limited RR types in pretty‑printer
- Negative cache TTL should ideally use SOA MINIMUM per RFC 2308

---

##  Contributing

1. Fork the repo and create a feature branch
2. Run `make` and add tests or demo commands in PR description
3. Open a PR — feedback and small refactors are welcome!

---

##  License

MIT — see `LICENSE` for details.

---

## Acknowledgements

- RFC 1035 (Domain Names — Implementation & Specification)
- Public resolvers used by default for convenience: Cloudflare (1.1.1.1), Google (8.8.8.8), Quad9 (9.9.9.9)
