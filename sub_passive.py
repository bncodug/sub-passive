#!/usr/bin/env python3
"""Passive subdomain enumeration.

Queries public datasets directly - certificate transparency logs, passive DNS
aggregators and web archives - and optionally aggregates the output of external
tools such as subfinder when they are installed.

Every source is passive: nothing in this script contacts the target domain.
Standard library only, Python 3.7+.
"""

import argparse
import concurrent.futures
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from typing import Callable, Dict, List, NamedTuple, Optional, Sequence, Set

VERSION = "2.0.0"

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/126.0.0.0 Safari/537.36 sub-passive"
)

DEFAULT_TIMEOUT = 40
EXTERNAL_TOOL_TIMEOUT = 300


# ==========================
# Hostname Hygiene
# ==========================
#
# Sources return hostnames wrapped in URLs, quoted inside JSON fragments,
# prefixed with wildcards or suffixed with ports. Everything is funnelled
# through normalize() so results deduplicate properly, and through in_scope()
# so third-party hosts seen in archived URLs never reach the output.


_HOST_TOKEN = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._-]*")
_LABEL = re.compile(r"^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?$")
_STRIP = "\"'`\\ \t\r\n,;()<>[]{}"


def normalize(raw: str) -> str:
    """Reduce any reference to a host down to a bare lowercase hostname."""
    host = raw.strip().lower()
    if not host:
        return ""

    scheme = host.find("://")
    if scheme >= 0:
        host = host[scheme + 3:]
    # Protocol-relative references: //cdn.example.com/app.js
    if host.startswith("//"):
        host = host[2:]
    # Userinfo in a URL, or an email address.
    at = host.rfind("@")
    if at >= 0:
        host = host[at + 1:]

    for separator in ("/", "?", "#"):
        cut = host.find(separator)
        if cut >= 0:
            host = host[:cut]
    # Strip :port, leaving bracketed IPv6 literals alone.
    if "]" not in host:
        colon = host.rfind(":")
        if colon >= 0:
            host = host[:colon]

    host = host.strip(_STRIP)
    while host.startswith("*."):
        host = host[2:]
    return host.strip(".")


def is_valid(host: str) -> bool:
    """Report whether host is a syntactically usable DNS name.

    Underscores are allowed because service records (_dmarc, _domainkey) are
    real assets worth reporting.
    """
    if not host or len(host) > 253 or ".." in host:
        return False

    labels = host.split(".")
    if len(labels) < 2:
        return False
    for label in labels:
        if not label or len(label) > 63 or not _LABEL.match(label):
            return False
    # An all-numeric TLD means this is an IP address, not a hostname.
    return not labels[-1].isdigit()


def in_scope(host: str, domain: str) -> bool:
    """Keep results anchored to the target.

    Checked explicitly rather than with a substring match, which would let
    "notexample.com" and "example.com.attacker.net" through.
    """
    return host == domain or host.endswith("." + domain)


def extract_hosts(text: str, domain: str) -> List[str]:
    """Mine in-scope hostnames out of arbitrary text (HTML, snippets, dumps).

    Tokens are matched greedily so that a lookalike such as
    "example.com.attacker.net" is captured whole and then rejected by
    in_scope(), instead of yielding a bogus "example.com".
    """
    found = []
    seen = set()
    for token in _HOST_TOKEN.findall(text):
        host = normalize(token)
        if host in seen or not is_valid(host) or not in_scope(host, domain):
            continue
        seen.add(host)
        found.append(host)
    return found


# ==========================
# HTTP Layer
# ==========================


class SourceError(Exception):
    """A source could not be queried."""


def api_key(provider: str) -> Optional[str]:
    """Return the API key for a provider, if one is exported.

    Keys are entirely optional; sources that need one are skipped without it.
    """
    return os.environ.get("SUB_PASSIVE_%s_KEY" % provider.upper()) or None


def http_get(
    url: str,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = DEFAULT_TIMEOUT,
    retries: int = 2,
) -> str:
    """Fetch a URL, retrying rate limits and server errors with backoff."""
    request_headers = {
        "User-Agent": USER_AGENT,
        "Accept": "*/*",
        # Requesting identity keeps the response readable without pulling in
        # gzip handling at every call site.
        "Accept-Encoding": "identity",
    }
    if headers:
        request_headers.update(headers)

    last_error = SourceError("no attempt made")
    for attempt in range(retries + 1):
        if attempt:
            time.sleep(min(2 ** attempt, 12))
        request = urllib.request.Request(url, headers=request_headers)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            detail = ""
            try:
                detail = exc.read(300).decode("utf-8", "replace").strip()
            except Exception:  # the body is best effort only
                pass
            last_error = SourceError("http %d: %s" % (exc.code, " ".join(detail.split())))
            if exc.code == 429:
                retry_after = exc.headers.get("Retry-After") if exc.headers else None
                if retry_after and retry_after.isdigit():
                    time.sleep(min(int(retry_after), 30))
                continue
            if 500 <= exc.code < 600:
                continue
            raise last_error
        except (urllib.error.URLError, OSError) as exc:
            last_error = SourceError(str(exc))
    raise last_error


def http_json(url: str, headers: Optional[Dict[str, str]] = None,
              timeout: int = DEFAULT_TIMEOUT, retries: int = 2):
    """Fetch a URL and decode it as JSON."""
    body = http_get(url, headers=headers, timeout=timeout, retries=retries)
    try:
        return json.loads(body)
    except ValueError as exc:
        raise SourceError("invalid JSON response: %s" % exc)


# ==========================
# Native Sources
# ==========================
#
# Each source returns raw strings: hostnames, or URLs containing them. The
# caller normalizes, scope-checks and deduplicates, so sources stay small.


def crtsh(domain: str) -> List[str]:
    query = urllib.parse.quote("%." + domain)
    # crt.sh is the richest keyless source and the least reliable one, so it
    # gets a long timeout and extra retries.
    entries = http_json("https://crt.sh/?q=%s&output=json" % query, timeout=120, retries=5)
    hosts = []
    for entry in entries:
        hosts.append(entry.get("common_name") or "")
        # name_value packs every SAN into one newline-separated field.
        hosts.extend((entry.get("name_value") or "").split("\n"))
    return hosts


def certspotter(domain: str) -> List[str]:
    url = (
        "https://api.certspotter.com/v1/issuances?domain=%s"
        "&include_subdomains=true&expand=dns_names" % urllib.parse.quote(domain)
    )
    headers = {}
    key = api_key("certspotter")
    if key:
        headers["Authorization"] = "Bearer " + key

    hosts = []
    after = ""
    # Anonymous access returns one truncated page; a key unlocks pagination.
    pages = 100 if key else 1
    for page in range(pages):
        page_url = url + ("&after=" + urllib.parse.quote(after) if after else "")
        try:
            entries = http_json(page_url, headers=headers, retries=3)
        except SourceError:
            if page:
                break  # keep what earlier pages produced
            raise
        if not entries:
            break
        for entry in entries:
            hosts.extend(entry.get("dns_names") or [])
        after = entries[-1].get("id") or ""
        if not after:
            break
    return hosts


def hackertarget(domain: str) -> List[str]:
    url = "https://api.hackertarget.com/hostsearch/?q=" + urllib.parse.quote(domain)
    key = api_key("hackertarget")
    if key:
        url += "&apikey=" + urllib.parse.quote(key)

    body = http_get(url)
    # The API signals problems with a 200 and a plain-text message.
    if "API count exceeded" in body:
        raise SourceError("free quota exhausted for this IP")
    if "error check your" in body:
        raise SourceError("upstream rejected the query")
    return [line.split(",")[0] for line in body.splitlines()]


def rapiddns(domain: str) -> List[str]:
    body = http_get("https://rapiddns.io/subdomain/%s?full=1" % urllib.parse.quote(domain))
    # RapidDNS only renders HTML, so the table is mined rather than parsed.
    return extract_hosts(body, domain)


def subdomain_center(domain: str) -> List[str]:
    return http_json("https://api.subdomain.center/?domain=" + urllib.parse.quote(domain))


def alienvault(domain: str) -> List[str]:
    url = ("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns"
           % urllib.parse.quote(domain))
    headers = {}
    key = api_key("alienvault")
    if key:
        headers["X-OTX-API-KEY"] = key
    data = http_json(url, headers=headers)
    return [record.get("hostname") or "" for record in data.get("passive_dns", [])]


def urlscan(domain: str) -> List[str]:
    headers = {}
    key = api_key("urlscan")
    if key:
        headers["API-Key"] = key

    hosts = []
    search_after = ""
    for page in range(10):
        url = ("https://urlscan.io/api/v1/search/?q=%s&size=100"
               % urllib.parse.quote("domain:" + domain))
        if search_after:
            url += "&search_after=" + urllib.parse.quote(search_after)
        try:
            data = http_json(url, headers=headers)
        except SourceError:
            if page:
                break
            raise
        results = data.get("results") or []
        for result in results:
            hosts.append((result.get("page") or {}).get("domain") or "")
            hosts.append((result.get("task") or {}).get("domain") or "")
            hosts.append((result.get("page") or {}).get("url") or "")
        if not data.get("has_more") or not results:
            break
        sort_values = results[-1].get("sort") or []
        if not sort_values:
            break
        search_after = ",".join(str(value) for value in sort_values)
    return hosts


def wayback(domain: str) -> List[str]:
    """Harvest hostnames from the Wayback Machine CDX index.

    The index is ordered by SURT key, so every apex and www URL is returned
    before the first subdomain. A busy site has more archived apex URLs than any
    sane limit, which truncates the response before a single subdomain appears -
    so they are filtered out server side. The apex is covered by every other
    source anyway, and dropping it cuts the response by an order of magnitude.
    """
    params = urllib.parse.urlencode({
        "url": domain,
        "matchType": "domain",
        "fl": "original",
        "collapse": "urlkey",
        "limit": "100000",
        "filter": r"!original:https?://(www\.)?%s/.*" % re.escape(domain),
    })
    body = http_get("https://web.archive.org/cdx/search/cdx?" + params, timeout=180)
    return body.splitlines()


def commoncrawl(domain: str) -> List[str]:
    indexes = http_json("https://index.commoncrawl.org/collinfo.json", timeout=60)
    hosts = []
    # Only the newest crawls are worth the wait; older ones repeat their hosts.
    for index in indexes[:2]:
        endpoint = index.get("cdx-api")
        if not endpoint:
            continue
        url = "%s?url=%s&output=json&fl=url&limit=50000" % (
            endpoint, urllib.parse.quote("*." + domain))
        try:
            body = http_get(url, timeout=180)
        except SourceError:
            continue
        for line in body.splitlines():
            try:
                hosts.append(json.loads(line).get("url") or "")
            except ValueError:
                continue
    return hosts


# --- sources that activate when a key is exported ---


def securitytrails(domain: str) -> List[str]:
    url = ("https://api.securitytrails.com/v1/domain/%s/subdomains"
           "?children_only=false&include_inactive=true" % urllib.parse.quote(domain))
    data = http_json(url, headers={"APIKEY": api_key("securitytrails") or ""})
    # SecurityTrails returns labels relative to the queried domain.
    return ["%s.%s" % (label, domain) for label in data.get("subdomains", [])]


def virustotal(domain: str) -> List[str]:
    key = api_key("virustotal") or ""
    url = ("https://www.virustotal.com/api/v3/domains/%s/subdomains?limit=40"
           % urllib.parse.quote(domain))
    hosts = []
    for page in range(25):
        try:
            data = http_json(url, headers={"x-apikey": key})
        except SourceError:
            if page:
                break
            raise
        hosts.extend(item.get("id") or "" for item in data.get("data", []))
        url = (data.get("links") or {}).get("next") or ""
        if not url:
            break
    return hosts


def chaos(domain: str) -> List[str]:
    url = "https://dns.projectdiscovery.io/dns/%s/subdomains" % urllib.parse.quote(domain)
    data = http_json(url, headers={"Authorization": api_key("chaos") or ""})
    return ["%s.%s" % (label, domain) if label else domain
            for label in data.get("subdomains", [])]


def shodan(domain: str) -> List[str]:
    url = "https://api.shodan.io/dns/domain/%s?key=%s" % (
        urllib.parse.quote(domain), urllib.parse.quote(api_key("shodan") or ""))
    data = http_json(url)
    hosts = ["%s.%s" % (label, domain) for label in data.get("subdomains", [])]
    for record in data.get("data", []):
        label = record.get("subdomain") or ""
        hosts.append("%s.%s" % (label, domain) if label else domain)
    return hosts


# ==========================
# External Tool Sources
# ==========================


def is_tool_installed(tool_name: str) -> bool:
    return shutil.which(tool_name) is not None


def run_command(command: List[str], timeout: int = EXTERNAL_TOOL_TIMEOUT) -> List[str]:
    """Run a command and return its output lines.

    A non-zero exit is not fatal on its own: these tools routinely exit non-zero
    after printing perfectly good results.
    """
    try:
        result = subprocess.run(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            universal_newlines=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise SourceError("timed out after %ds" % timeout)
    except OSError as exc:
        raise SourceError(str(exc))

    output = (result.stdout or "").strip().splitlines()
    if result.returncode != 0 and not output:
        detail = " ".join((result.stderr or "").split())[:120]
        raise SourceError("exit %d: %s" % (result.returncode, detail))
    return output


def subfinder(domain: str) -> List[str]:
    return run_command(["subfinder", "-d", domain, "-all", "-silent"])


def assetfinder(domain: str) -> List[str]:
    return run_command(["assetfinder", "--subs-only", domain])


def waymore(domain: str) -> List[str]:
    return run_command(["waymore", "-i", domain, "-mode", "U"])


# ==========================
# Source Registry
# ==========================


class Source(NamedTuple):
    name: str
    run: Callable[[str], List[str]]
    description: str
    default: bool = True
    binary: str = ""      # external tool that must be installed
    provider: str = ""    # environment key required to run


SOURCES: List[Source] = [
    Source("crtsh", crtsh, "certificate transparency logs (crt.sh)"),
    Source("certspotter", certspotter, "SSLMate CertSpotter CT issuances"),
    Source("hackertarget", hackertarget, "HackerTarget passive DNS"),
    Source("rapiddns", rapiddns, "RapidDNS passive DNS records"),
    Source("subdomaincenter", subdomain_center,
           "subdomain.center passive DNS (high volume, low precision)"),
    Source("alienvault", alienvault, "AlienVault OTX passive DNS"),
    Source("urlscan", urlscan, "urlscan.io scan history"),
    Source("wayback", wayback, "Wayback Machine CDX index"),
    Source("commoncrawl", commoncrawl,
           "Common Crawl URL index (slow, frequently overloaded)", default=False),

    Source("securitytrails", securitytrails, "SecurityTrails", provider="securitytrails"),
    Source("virustotal", virustotal, "VirusTotal", provider="virustotal"),
    Source("chaos", chaos, "ProjectDiscovery Chaos", provider="chaos"),
    Source("shodan", shodan, "Shodan DNS database", provider="shodan"),

    Source("subfinder", subfinder, "subfinder, if installed", binary="subfinder"),
    Source("assetfinder", assetfinder, "assetfinder, if installed", binary="assetfinder"),
    Source("waymore", waymore, "waymore, if installed", binary="waymore"),
]

SOURCES_BY_NAME: Dict[str, Source] = {source.name: source for source in SOURCES}

# Retained so that `--tools subfinder assetfinder waymore` keeps working.
TOOLS: Dict[str, Callable[[str], List[str]]] = {
    source.name: source.run for source in SOURCES
}


# ==========================
# Terminal Output
# ==========================


def _use_color() -> bool:
    return sys.stderr.isatty() and not os.environ.get("NO_COLOR")


def paint(text: str, code: str) -> str:
    return "\033[%sm%s\033[0m" % (code, text) if _use_color() else text


def log(message: str) -> None:
    """Write progress to stderr, keeping stdout clean for hostnames."""
    print(message, file=sys.stderr, flush=True)


def silence_stdout() -> None:
    """Point stdout at /dev/null after the reader has gone away.

    Without this, a pipeline that stops early (`... | head`) leaves the
    interpreter with an unwritable stdout, and Python reports a second
    BrokenPipeError while flushing at exit.
    """
    try:
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
    except OSError:
        pass


# ==========================
# Orchestration Layer
# ==========================


class Stat(NamedTuple):
    name: str
    found: int
    unique: int
    seconds: float
    error: str = ""
    skipped: str = ""


class Findings(NamedTuple):
    domain: str
    hosts: Dict[str, List[str]]   # host -> sources that reported it
    stats: List[Stat]
    seconds: float


def select_sources(names: Optional[Sequence[str]], include_all: bool) -> List[Source]:
    if names:
        return [SOURCES_BY_NAME[name] for name in names]
    return [source for source in SOURCES if source.default or include_all]


def skip_reason(source: Source) -> str:
    """Explain why a source cannot run, or return "" if it can."""
    if source.binary and not is_tool_installed(source.binary):
        return "not installed"
    if source.provider and not api_key(source.provider):
        return "no SUB_PASSIVE_%s_KEY" % source.provider.upper()
    return ""


def run_sources(domain: str, sources: Sequence[Source], threads: int,
                emit: Callable[[str], None]) -> Findings:
    """Query every source concurrently and merge what they return."""
    started = time.time()
    hosts: Dict[str, List[str]] = {}
    stats: List[Stat] = []
    runnable = []

    for source in sources:
        reason = skip_reason(source)
        if reason:
            stats.append(Stat(source.name, 0, 0, 0.0, skipped=reason))
            log("  %s %-16s %s" % (paint("-", "2"), source.name, paint(reason, "2")))
            continue
        runnable.append(source)

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        future_map = {}
        for source in runnable:
            future = executor.submit(source.run, domain)
            future_map[future] = (source, time.time())

        for future in concurrent.futures.as_completed(future_map):
            source, source_started = future_map[future]
            elapsed = time.time() - source_started
            try:
                raw_results = future.result()
            except SourceError as exc:
                stats.append(Stat(source.name, 0, 0, elapsed, error=str(exc)))
                log("  %s %-16s %s" % (paint("x", "31"), source.name,
                                       paint(str(exc)[:96], "2")))
                continue
            except Exception as exc:  # one broken source must not end the run
                stats.append(Stat(source.name, 0, 0, elapsed, error=repr(exc)))
                log("  %s %-16s %s" % (paint("x", "31"), source.name,
                                       paint(repr(exc)[:96], "2")))
                continue

            # Merging happens here, in one thread, so no locking is needed.
            found = 0
            unique = 0
            seen: Set[str] = set()
            for raw in raw_results:
                host = normalize(raw)
                if not is_valid(host) or not in_scope(host, domain):
                    continue
                if host not in seen:
                    seen.add(host)
                    found += 1
                if host not in hosts:
                    hosts[host] = []
                    unique += 1
                    emit(host)
                if source.name not in hosts[host]:
                    hosts[host].append(source.name)

            stats.append(Stat(source.name, found, unique, elapsed))
            detail = "%d found, %d new" % (found, unique)
            log("  %s %-16s %-22s %s" % (paint("+", "32"), source.name, detail,
                                         paint("%.1fs" % elapsed, "2")))

    stats.sort(key=lambda stat: stat.name)
    return Findings(domain, hosts, stats, time.time() - started)


def sort_hosts(hosts: Sequence[str]) -> List[str]:
    """Order by label depth then alphabetically, so apex-adjacent names lead."""
    return sorted(hosts, key=lambda host: (host.count("."), host))


# ==========================
# Output
# ==========================


def save_results(domain: str, results: Sequence[str], output_dir: str) -> str:
    os.makedirs(output_dir, exist_ok=True)

    filename = "%s-subdomains-%s.txt" % (domain, datetime.now().strftime("%Y-%m-%d"))
    path = os.path.join(output_dir, filename)

    with open(path, "w") as handle:
        for subdomain in sort_hosts(results):
            handle.write(subdomain + "\n")

    return path


def save_json(findings: Findings, output_dir: str) -> str:
    os.makedirs(output_dir, exist_ok=True)

    filename = "%s-subdomains-%s.json" % (findings.domain,
                                          datetime.now().strftime("%Y-%m-%d"))
    path = os.path.join(output_dir, filename)

    report = {
        "domain": findings.domain,
        "generated": datetime.now().isoformat(),
        "tool": "sub-passive",
        "version": VERSION,
        "duration_seconds": round(findings.seconds, 2),
        "summary": {
            "hosts": len(findings.hosts),
            "sources_queried": len([s for s in findings.stats if not s.skipped]),
            "sources_failed": len([s for s in findings.stats if s.error]),
        },
        "hosts": [
            {"host": host, "sources": sorted(findings.hosts[host])}
            for host in sort_hosts(list(findings.hosts))
        ],
        "sources": [dict(stat._asdict()) for stat in findings.stats],
    }
    with open(path, "w") as handle:
        json.dump(report, handle, indent=2)
        handle.write("\n")

    return path


def print_stats(findings: Findings) -> None:
    log("\n   %s" % paint("source           found   unique   time", "2"))
    for stat in sorted(findings.stats, key=lambda s: (-s.unique, -s.found)):
        if stat.skipped:
            continue
        note = paint("  error", "31") if stat.error else ""
        log("   %-16s %5d   %6d   %5.1fs%s"
            % (stat.name, stat.found, stat.unique, stat.seconds, note))


def load_known(paths: Sequence[str]) -> Set[str]:
    """Read hostnames from previous runs, for new-asset detection."""
    known: Set[str] = set()
    for path in paths:
        with open(path) as handle:
            for line in handle:
                host = normalize(line)
                if is_valid(host):
                    known.add(host)
    return known


# ==========================
# Scan
# ==========================


def passive_scan(domain: str, tools: Optional[Sequence[str]], output_dir: str,
                 threads: int = 12, include_all: bool = False, want_json: bool = False,
                 silent: bool = False, show_stats: bool = False,
                 known: Optional[Set[str]] = None, only_new: bool = False) -> int:
    """Enumerate one domain. Returns the number of hosts reported."""
    domain = normalize(domain)
    if not is_valid(domain):
        log("[!] Invalid domain, skipping")
        return 0

    sources = select_sources(tools, include_all)
    if not silent:
        log("%s %s %s" % (paint("[>]", "36"), paint(domain, "1"),
                          paint("(%d sources)" % len(sources), "2")))

    known = known or set()
    # Stream to stdout when the output is piped or redirected, so the script
    # drops into a pipeline; keep an interactive terminal readable.
    state = {"streaming": silent or not sys.stdout.isatty()}

    def emit(host: str) -> None:
        if not state["streaming"] or (only_new and host in known):
            return
        try:
            print(host, flush=True)
        except BrokenPipeError:
            # The reader stopped early (`| head`). Finish the run quietly so the
            # output file is still written.
            state["streaming"] = False
            silence_stdout()

    findings = run_sources(domain, sources, threads, emit)

    reported = [host for host in findings.hosts if not (only_new and host in known)]
    new_hosts = [host for host in findings.hosts if host not in known]

    if not silent:
        summary = "   %s hosts" % paint(str(len(findings.hosts)), "1;32")
        if known:
            summary += "  ·  %s new" % paint(str(len(new_hosts)), "1;36")
        log("\n%s %s\n%s" % (paint("==", "2"), paint(domain, "1"), summary))
        log("   %s" % paint("%d sources, %d failed, %.1fs" % (
            len([s for s in findings.stats if not s.skipped]),
            len([s for s in findings.stats if s.error]),
            findings.seconds), "2"))

    if reported:
        path = save_results(domain, reported, output_dir)
        if not silent:
            log("   %s %s" % (paint("->", "2"), path))
        if want_json:
            json_path = save_json(findings, output_dir)
            if not silent:
                log("   %s %s" % (paint("->", "2"), json_path))
    elif not silent:
        log("   %s" % paint("nothing found, no file written", "2"))

    if show_stats and not silent:
        print_stats(findings)

    return len(reported)


# ==========================
# CLI
# ==========================


def list_sources() -> None:
    print("%-16s %-9s %s" % ("SOURCE", "AUTH", "NOTES"))
    for source in SOURCES:
        auth = source.provider or ("binary" if source.binary else "none")
        notes = source.description
        if not source.default:
            notes += "  [needs --all or --tools]"
        print("%-16s %-9s %s" % (source.name, auth, notes))
    keyless = len([s for s in SOURCES if not s.provider and not s.binary])
    print("\n%d sources, %d need no credentials and no external tools."
          % (len(SOURCES), keyless))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Passive Subdomain Scanner",
        epilog="Hostnames go to stdout when piped; progress goes to stderr.",
    )

    parser.add_argument("domain", nargs="*", help="Target domain (e.g. example.com)")

    parser.add_argument("-o", "--output-dir", default=".", help="Output directory")

    parser.add_argument(
        "-t",
        "--tools",
        nargs="+",
        choices=sorted(TOOLS.keys()),
        default=None,
        metavar="SOURCE",
        help="Sources to use (default: every source that needs no setup)"
    )

    parser.add_argument("--all", action="store_true",
                        help="Also query slow and unreliable sources")
    parser.add_argument("--list-sources", action="store_true",
                        help="List available sources and exit")
    parser.add_argument("--threads", type=int, default=12,
                        help="Sources queried in parallel (default: 12)")
    parser.add_argument("--json", action="store_true",
                        help="Also write a JSON report")
    parser.add_argument("--stats", action="store_true",
                        help="Print a per-source contribution table")
    parser.add_argument("--silent", action="store_true",
                        help="Print only hostnames")
    parser.add_argument("--known", nargs="+", metavar="FILE", default=None,
                        help="Files of previously seen hosts, for new-asset detection")
    parser.add_argument("--only-new", action="store_true",
                        help="Report only hosts absent from --known")
    parser.add_argument("--version", action="version", version="sub-passive " + VERSION)

    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.list_sources:
        list_sources()
        return

    domains = list(args.domain)
    # Accept a list of domains on stdin when none were given on the command line.
    if not domains and not sys.stdin.isatty():
        domains = [line.strip() for line in sys.stdin if line.strip()]
    if not domains:
        log("[!] No target domain given")
        sys.exit(1)

    known = load_known(args.known) if args.known else set()
    if args.only_new and not known:
        log("[!] --only-new without --known: every host counts as new")

    total = 0
    for domain in domains:
        total += passive_scan(
            domain,
            args.tools,
            args.output_dir,
            threads=args.threads,
            include_all=args.all,
            want_json=args.json,
            silent=args.silent,
            show_stats=args.stats,
            known=known,
            only_new=args.only_new,
        )

    # A distinct code lets automation tell "nothing found" apart from a crash.
    if total == 0:
        sys.exit(2)


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        silence_stdout()
    except KeyboardInterrupt:
        log("\n[!] Interrupted")
        sys.exit(130)
