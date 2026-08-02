# Passive Subdomain Scanner

A simple, fast, and modular **passive subdomain enumeration tool**. It queries
public datasets directly — certificate transparency logs, passive DNS
aggregators and web archives — and also aggregates the output of external recon
tools when you have them installed.

No dependencies, no API keys, and no external tools required: `python3
sub_passive.py example.com` works on a clean machine.

## Features

* Passive enumeration only (no direct interaction with the target)
* **13 built-in sources**, 9 of which need no credentials and no external tools
* External tools (`subfinder`, `assetfinder`, `waymore`) still used when present
* Concurrent execution, with retries and backoff on rate limits and outages
* Results normalized, scope-filtered and deduplicated
* Per-source statistics, so you can see which sources actually contribute
* Text and JSON output, plus new-asset detection between runs
* Pipe-friendly: hostnames on stdout, progress on stderr

---

## Sources

Keyless, enabled by default:

| Source            | Data                                             |
| ----------------- | ------------------------------------------------ |
| `crtsh`           | Certificate Transparency logs                     |
| `certspotter`     | SSLMate CertSpotter CT issuances                  |
| `hackertarget`    | passive DNS                                       |
| `rapiddns`        | passive DNS records                               |
| `subdomaincenter` | aggregated passive DNS (high volume, low precision) |
| `alienvault`      | AlienVault OTX passive DNS                        |
| `urlscan`         | urlscan.io scan history                           |
| `wayback`         | Wayback Machine CDX index                         |
| `commoncrawl`     | Common Crawl URL index (`--all`, slow)            |

Enabled when a key is exported: `securitytrails`, `virustotal`, `chaos`,
`shodan`. Used when installed: `subfinder`, `assetfinder`, `waymore`.

Run `python3 sub_passive.py --list-sources` to see the full list.

---

## Installation

```bash
git clone https://github.com/bncodug/sub-passive.git
cd sub-passive
python3 sub_passive.py example.com
```

Requires Python 3.7+ and nothing else — the script uses only the standard
library.

### Optional: external tools

The three original tools are still supported and are used automatically when
found in `$PATH`. They are skipped with a note when absent.

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/tomnomnom/assetfinder@latest
```

For `waymore`, see https://github.com/xnl-h4ck3r/waymore

### Optional: API keys

Every key is optional; sources without one are skipped, never failed.

```bash
export SUB_PASSIVE_VIRUSTOTAL_KEY=...
export SUB_PASSIVE_SECURITYTRAILS_KEY=...
export SUB_PASSIVE_CHAOS_KEY=...
export SUB_PASSIVE_SHODAN_KEY=...
```

Keys also improve keyless sources: `SUB_PASSIVE_CERTSPOTTER_KEY`,
`SUB_PASSIVE_URLSCAN_KEY`, `SUB_PASSIVE_ALIENVAULT_KEY`,
`SUB_PASSIVE_HACKERTARGET_KEY`.

---

## Using a proxy

The standard environment variables are honoured; there is no proxy flag.

```bash
export https_proxy=http://127.0.0.1:8080
export http_proxy=http://127.0.0.1:8080
export no_proxy=localhost,127.0.0.1        # optional bypass list
```

Or for a single run:

```bash
https_proxy=http://127.0.0.1:8080 python3 sub_passive.py example.com
```

Uppercase (`HTTPS_PROXY`) and lowercase (`https_proxy`) are both read; if both
are set, the lowercase one wins.

SOCKS is not supported — the standard library has no SOCKS client. A `socks5://`
URL is treated as an ordinary HTTP proxy and `ALL_PROXY` is ignored, so set
`https_proxy` to an HTTP proxy. A misconfigured proxy fails loudly: sources
report a connection error rather than silently going direct.

---

## Usage

```bash
python3 sub_passive.py [-h] [-o OUTPUT_DIR] [-t SOURCE ...] [--all] [--json]
                       [--stats] [--silent] [--threads N]
                       [--known FILE ...] [--only-new] [--list-sources]
                       domain [domain ...]
```

### Arguments

| Argument           | Description                                        |
| ------------------ | -------------------------------------------------- |
| `domain`           | Target domain(s), or a list piped on stdin          |
| `-o, --output-dir` | Output directory (default: current directory)       |
| `-t, --tools`      | One or more sources to use                          |
| `--all`            | Also query slow and unreliable sources              |
| `--json`           | Also write a JSON report                            |
| `--stats`          | Print a per-source contribution table               |
| `--silent`         | Print only hostnames                                |
| `--threads`        | Sources queried in parallel (default: 12)           |
| `--known`          | Files of previously seen hosts                      |
| `--only-new`       | Report only hosts absent from `--known`             |
| `--list-sources`   | List available sources and exit                     |

---

## Examples

### Run every source that needs no setup (default)

```bash
python3 sub_passive.py example.com
```

### Use specific sources

```bash
python3 sub_passive.py example.com -t crtsh certspotter subfinder
```

### Save output to a directory, with a JSON report and source stats

```bash
python3 sub_passive.py example.com -o results/ --json --stats
```

### Pipe into another tool

```bash
python3 sub_passive.py example.com --silent | httpx
cat scope.txt | python3 sub_passive.py --silent -o results/
```

### Monitor a target for new assets

```bash
python3 sub_passive.py example.com -o results/                       # baseline
python3 sub_passive.py example.com --known results/*.txt --only-new  # only new
```

---

## Output

Results are saved as before:

```bash
<domain>-subdomains-YYYY-MM-DD.txt
```

With `--json`, a structured report is written alongside it, recording which
sources reported each host plus per-source timings and errors.

Exit codes: `0` hosts found, `2` ran cleanly but found nothing, `1` fatal error.

---

## How It Works

1. Selected sources are queried concurrently
2. Native sources call public APIs; external tools are run as subprocesses
3. Every result is normalized (scheme, port, wildcard and case stripped) and
   checked against the target domain, so out-of-scope hosts are discarded
4. Results are aggregated, deduplicated and written to the output file

---

## Notes

* This tool performs **passive reconnaissance only** — it never sends a packet
  to the target
* Results include hosts that no longer resolve, which is the point of passive
  discovery; resolve the list before acting on it
* A source failing (rate limit, outage) never ends the run

---

## Disclaimer

This tool is intended for **educational and authorized security testing only**.
Do not use it against systems you do not own or have permission to test.


---

## License

MIT License
