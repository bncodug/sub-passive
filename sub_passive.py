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
import gzip
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
import zlib
from datetime import datetime
from typing import Callable, Dict, List, NamedTuple, Optional, Sequence, Set

VERSION = "2.1.0"

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/126.0.0.0 Safari/537.36 sub-passive"
)

DEFAULT_TIMEOUT = 40
EXTERNAL_TOOL_TIMEOUT = 300

# Set by --timeout. The slowest sources ask for a longer timeout than
# DEFAULT_TIMEOUT (crt.sh 120s, the archives 180s), so a flag that only changed
# the default would quietly fail to apply to exactly the sources a user is
# trying to rein in. This overrides every per-request value instead.
TIMEOUT_OVERRIDE: Optional[int] = None


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
    """Reduce any reference to a host down to a bare lowercase hostname.

    Anything that is not a string normalizes to "" rather than raising: sources
    hand back decoded JSON, and one stray null or number in a list should cost
    that one entry, not every result the source returned.
    """
    if not isinstance(raw, str):
        return ""
    host = raw.strip().lower()
    if not host:
        return ""

    scheme = host.find("://")
    if scheme >= 0:
        host = host[scheme + 3:]
    # Protocol-relative references: //cdn.example.com/app.js
    if host.startswith("//"):
        host = host[2:]

    # The authority ends at the first "/", "?" or "#". Cutting the path off
    # before looking for userinfo matters: archived URLs routinely carry an "@"
    # in a query string, and trimming at that "@" first would throw away the
    # real host and keep a fragment of the query instead.
    for separator in ("/", "?", "#"):
        cut = host.find(separator)
        if cut >= 0:
            host = host[:cut]
    # Userinfo in a URL, or an email address.
    at = host.rfind("@")
    if at >= 0:
        host = host[at + 1:]
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


def json_strings(payload) -> List[str]:
    """Collect every string in a decoded JSON document, at any depth.

    Providers reshape their responses without warning, and a source that reads
    one hard-coded field silently returns nothing the day that field is renamed.
    Handing the caller every string instead costs nothing, because normalize(),
    is_valid() and in_scope() discard anything that is not an in-scope host.
    """
    found: List[str] = []
    stack = [payload]
    while stack:
        node = stack.pop()
        if isinstance(node, str):
            found.append(node)
        elif isinstance(node, dict):
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
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


def _read_body(response) -> str:
    """Read a response, transparently decompressing it.

    The archive sources return tens of megabytes of URLs, so asking for gzip is
    worth the few lines it costs. Servers are free to ignore the request header,
    and some send a compressed body regardless of what was asked for, so the
    encoding is taken from the response rather than assumed.
    """
    raw = response.read()
    encoding = (response.headers.get("Content-Encoding") or "").lower().strip()
    if encoding in ("gzip", "x-gzip"):
        try:
            raw = gzip.decompress(raw)
        except OSError as exc:
            raise SourceError("could not decompress gzip response: %s" % exc)
    elif encoding == "deflate":
        try:
            raw = zlib.decompress(raw)
        except zlib.error:
            # Raw deflate streams without the zlib wrapper are also seen here.
            try:
                raw = zlib.decompress(raw, -zlib.MAX_WBITS)
            except zlib.error as exc:
                raise SourceError("could not decompress deflate response: %s" % exc)
    return raw.decode("utf-8", "replace")


_UNPRINTABLE = re.compile(r"[^\x20-\x7e\xa0-\uffff]")


def _readable(text: str, limit: int = 200) -> str:
    """Fold server-supplied text into one short line that is safe to print.

    Error bodies are written by whatever is on the other end and land on a
    terminal, so control characters - escape sequences above all - are dropped
    rather than passed through.
    """
    return " ".join(_UNPRINTABLE.sub(" ", text).split())[:limit].strip()


def _inflate_partial(raw: bytes, encoding: str) -> bytes:
    """Best-effort decompress of a body that was only read as far as needed."""
    wbits = 16 + zlib.MAX_WBITS if encoding in ("gzip", "x-gzip") else zlib.MAX_WBITS
    for bits in (wbits, -zlib.MAX_WBITS):
        try:
            # An incremental decompressor, because the tail of the stream is
            # deliberately missing: it returns what it has instead of raising.
            return zlib.decompressobj(bits).decompress(raw)
        except zlib.error:
            continue
    return raw


def _error_detail(exc) -> str:
    """Summarize an error response body for a log line.

    The body arrives under whatever Content-Encoding was negotiated, and this
    request asked for gzip, so reading it raw is how a 404 page ends up on
    screen as mojibake. Anything still unreadable after decompressing - brotli,
    say, or an actually binary body - is described rather than printed.
    """
    try:
        raw = exc.read(4096)
    except Exception:   # the body is best effort only
        return ""
    if not raw:
        return ""

    headers = getattr(exc, "headers", None)
    encoding = ""
    if headers:
        encoding = (headers.get("Content-Encoding") or "").lower().strip()
    body = _inflate_partial(raw, encoding) if encoding else raw

    text = _readable(body.decode("utf-8", "replace"))
    if not text or text.count("\ufffd") * 4 > len(text):
        return "<%d bytes of unreadable %s body>" % (len(raw), encoding or "response")
    return text


def http_get(
    url: str,
    headers: Optional[Dict[str, str]] = None,
    timeout: Optional[int] = None,
    retries: int = 2,
) -> str:
    """Fetch a URL, retrying rate limits and server errors with backoff.

    Timeouts are resolved at call time, not baked in as default arguments, so
    that --timeout applies: an explicit override wins over the per-source value,
    which in turn wins over DEFAULT_TIMEOUT.
    """
    if TIMEOUT_OVERRIDE is not None:
        timeout = TIMEOUT_OVERRIDE
    elif timeout is None:
        timeout = DEFAULT_TIMEOUT
    request_headers = {
        "User-Agent": USER_AGENT,
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate",
    }
    if headers:
        request_headers.update(headers)

    last_error = SourceError("no attempt made")
    for attempt in range(retries + 1):
        final_attempt = attempt == retries
        if attempt:
            time.sleep(min(2 ** attempt, 12))
        request = urllib.request.Request(url, headers=request_headers)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return _read_body(response)
        except urllib.error.HTTPError as exc:
            detail = _error_detail(exc)
            last_error = SourceError("http %d: %s" % (exc.code, detail)
                                     if detail else "http %d" % exc.code)
            if exc.code == 429:
                # Honour Retry-After, but never sleep on a request we have
                # already decided not to repeat.
                retry_after = exc.headers.get("Retry-After") if exc.headers else None
                if retry_after and retry_after.strip().isdigit() and not final_attempt:
                    time.sleep(min(int(retry_after), 30))
                continue
            if 500 <= exc.code < 600:
                continue
            raise last_error
        except (urllib.error.URLError, OSError) as exc:
            last_error = SourceError(str(exc))
    raise last_error


def http_json(url: str, headers: Optional[Dict[str, str]] = None,
              timeout: Optional[int] = None, retries: int = 2):
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
    data = http_json("https://api.subdomain.center/?domain=" + urllib.parse.quote(domain))
    # The endpoint answers errors with a JSON object rather than an HTTP status;
    # iterating that would yield its keys as if they were hostnames.
    if not isinstance(data, list):
        raise SourceError("unexpected response: %s" % str(data)[:120])
    return data


def alienvault(domain: str) -> List[str]:
    """AlienVault OTX passive DNS.

    OTX closed anonymous access to this endpoint - it now answers 429 with
    "Anonymous access to this endpoint is limited" - so the source is registered
    as key-required and skipped cleanly when SUB_PASSIVE_ALIENVAULT_KEY is unset.
    """
    url = ("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns"
           % urllib.parse.quote(domain))
    data = http_json(url, headers={"X-OTX-API-KEY": api_key("alienvault") or ""})
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


def hudsonrock(domain: str) -> List[str]:
    """URLs seen in infostealer logs, via Hudson Rock's free OSINT endpoint.

    A small source, but it reports hosts that were reached by a real browser on
    a compromised machine, so it surfaces internal and staging names that never
    appear in certificates or crawls.
    """
    url = ("https://cavalier.hudsonrock.com/api/json/v2/osint-tools/"
           "urls-by-domain?domain=" + urllib.parse.quote(domain))
    return json_strings(http_json(url))


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


def fullhunt(domain: str) -> List[str]:
    url = "https://fullhunt.io/api/v1/domain/%s/subdomains" % urllib.parse.quote(domain)
    data = http_json(url, headers={"X-API-KEY": api_key("fullhunt") or ""})
    return data.get("hosts") or []


def bevigil(domain: str) -> List[str]:
    url = "https://osint.bevigil.com/api/%s/subdomains/" % urllib.parse.quote(domain)
    data = http_json(url, headers={"X-Access-Token": api_key("bevigil") or ""})
    return data.get("subdomains") or []


def leakix(domain: str) -> List[str]:
    url = "https://leakix.net/api/subdomains/%s" % urllib.parse.quote(domain)
    data = http_json(url, headers={"api-key": api_key("leakix") or "",
                                   "Accept": "application/json"})
    return json_strings(data)


def dnsdumpster(domain: str) -> List[str]:
    url = "https://api.dnsdumpster.com/domain/%s" % urllib.parse.quote(domain)
    data = http_json(url, headers={"X-API-Key": api_key("dnsdumpster") or ""})
    # The report splits hosts across a/cname/mx/ns sections, each with its own
    # record shape, so every string in the document is harvested instead.
    return json_strings(data)


def whoisxmlapi(domain: str) -> List[str]:
    url = "https://subdomains.whoisxmlapi.com/api/v1?apiKey=%s&domainName=%s" % (
        urllib.parse.quote(api_key("whoisxmlapi") or ""), urllib.parse.quote(domain))
    data = http_json(url)
    return json_strings(data.get("result") or {})


def netlas(domain: str) -> List[str]:
    """Netlas domain index, paged 20 at a time (its maximum page size)."""
    key = api_key("netlas") or ""
    query = urllib.parse.quote("domain:*.%s" % domain)
    hosts: List[str] = []
    for start in range(0, 1000, 20):
        url = ("https://app.netlas.io/api/domains/?q=%s&source_type=include"
               "&fields=domain&start=%d" % (query, start))
        try:
            data = http_json(url, headers={"X-API-Key": key})
        except SourceError:
            if start:
                break  # keep what earlier pages produced
            raise
        items = data.get("items") or []
        if not items:
            break
        hosts.extend(json_strings(items))
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


def run_tool(command: List[str], domain: str,
             timeout: int = EXTERNAL_TOOL_TIMEOUT) -> List[str]:
    """Run an external tool and mine hostnames out of whatever it prints.

    Output formats differ per tool and per major version: bare hostnames, full
    URLs, or amass's "host (FQDN) --> a_record --> addr". Extracting hosts from
    the text rather than treating each line as a hostname keeps this working
    across all of them, and across the next format change.
    """
    return extract_hosts("\n".join(run_command(command, timeout=timeout)), domain)


def subfinder(domain: str) -> List[str]:
    return run_tool(["subfinder", "-d", domain, "-all", "-silent"], domain)


def assetfinder(domain: str) -> List[str]:
    return run_tool(["assetfinder", "--subs-only", domain], domain)


def waymore(domain: str) -> List[str]:
    return run_tool(["waymore", "-i", domain, "-mode", "U"], domain)


def amass(domain: str) -> List[str]:
    # No -silent: the flag comes and goes between major versions, and the
    # banner it suppresses is filtered out by host extraction anyway.
    return run_tool(["amass", "enum", "-passive", "-d", domain], domain)


def findomain(domain: str) -> List[str]:
    return run_tool(["findomain", "-t", domain, "-q"], domain)


def gau(domain: str) -> List[str]:
    return run_tool(["gau", "--subs", domain], domain)


def waybackurls(domain: str) -> List[str]:
    return run_tool(["waybackurls", domain], domain)


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
    # Keyless, on by default.
    Source("crtsh", crtsh, "certificate transparency logs (crt.sh)"),
    Source("certspotter", certspotter, "SSLMate CertSpotter CT issuances"),
    Source("hackertarget", hackertarget, "HackerTarget passive DNS"),
    Source("rapiddns", rapiddns, "RapidDNS passive DNS records"),
    Source("urlscan", urlscan, "urlscan.io scan history"),
    Source("wayback", wayback, "Wayback Machine CDX index"),
    Source("hudsonrock", hudsonrock, "Hudson Rock infostealer URL dataset"),

    # Keyless, but opt-in: too slow, or too noisy to leave on by default.
    Source("commoncrawl", commoncrawl,
           "Common Crawl URL index (slow, frequently overloaded)", default=False),
    # Measured against hackerone.com: 497 of the 523 hosts in a default run came
    # from here alone, and spot-checking them found names that cannot be real
    # (s3-ap-northeast-1, 0a.227, long runs of bare numbers). It is kept because
    # it does occasionally surface something real, but it has to be asked for.
    Source("subdomaincenter", subdomain_center,
           "subdomain.center passive DNS (very high volume, unverified)",
           default=False),

    # Activated by exporting SUB_PASSIVE_<NAME>_KEY.
    Source("alienvault", alienvault,
           "AlienVault OTX passive DNS", provider="alienvault"),
    Source("securitytrails", securitytrails, "SecurityTrails", provider="securitytrails"),
    Source("virustotal", virustotal, "VirusTotal", provider="virustotal"),
    Source("chaos", chaos, "ProjectDiscovery Chaos", provider="chaos"),
    Source("shodan", shodan, "Shodan DNS database", provider="shodan"),
    Source("fullhunt", fullhunt, "FullHunt attack surface database", provider="fullhunt"),
    Source("bevigil", bevigil, "BeVigil mobile-app OSINT", provider="bevigil"),
    Source("leakix", leakix, "LeakIX subdomain index", provider="leakix"),
    Source("dnsdumpster", dnsdumpster, "DNSDumpster DNS records", provider="dnsdumpster"),
    Source("netlas", netlas, "Netlas domain index", provider="netlas"),
    Source("whoisxmlapi", whoisxmlapi,
           "WhoisXML API subdomains", provider="whoisxmlapi"),

    # Used when the binary is on $PATH.
    Source("subfinder", subfinder, "subfinder, if installed", binary="subfinder"),
    Source("assetfinder", assetfinder, "assetfinder, if installed", binary="assetfinder"),
    Source("waymore", waymore, "waymore, if installed", binary="waymore"),
    Source("amass", amass, "amass passive mode, if installed", binary="amass"),
    Source("findomain", findomain, "findomain, if installed", binary="findomain"),
    Source("gau", gau, "gau, if installed", binary="gau"),
    Source("waybackurls", waybackurls, "waybackurls, if installed",
           binary="waybackurls"),
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


def select_sources(names: Optional[Sequence[str]], include_all: bool,
                   exclude: Optional[Sequence[str]] = None) -> List[Source]:
    """Resolve the requested source names, keeping registry order.

    Duplicates are collapsed so that `-t crtsh crtsh` queries crt.sh once.
    """
    if names:
        unknown = sorted(set(names) - set(SOURCES_BY_NAME))
        if unknown:
            raise ValueError("unknown source(s): %s" % ", ".join(unknown))
        wanted = set(names)
        chosen = [source for source in SOURCES if source.name in wanted]
    else:
        chosen = [source for source in SOURCES if source.default or include_all]

    if exclude:
        skipped = set(exclude)
        chosen = [source for source in chosen if source.name not in skipped]
    return chosen


def skip_reason(source: Source) -> str:
    """Explain why a source cannot run, or return "" if it can."""
    if source.binary and not is_tool_installed(source.binary):
        return "not installed"
    if source.provider and not api_key(source.provider):
        return "no SUB_PASSIVE_%s_KEY" % source.provider.upper()
    return ""


def run_sources(domain: str, sources: Sequence[Source], threads: int,
                emit: Callable[[str], None], silent: bool = False) -> Findings:
    """Query every source concurrently and merge what they return.

    Progress is written to stderr as each source lands, unless silent is set:
    --silent promises hostnames and nothing else, on either stream.
    """
    started = time.time()

    def progress(message: str) -> None:
        if not silent:
            log(message)

    hosts: Dict[str, List[str]] = {}
    stats: List[Stat] = []
    runnable = []

    for source in sources:
        reason = skip_reason(source)
        if reason:
            stats.append(Stat(source.name, 0, 0, 0.0, skipped=reason))
            progress("  %s %-16s %s"
                     % (paint("-", "2"), source.name, paint(reason, "2")))
            continue
        runnable.append(source)

    if not runnable:
        return Findings(domain, hosts, stats, time.time() - started)

    def timed(source: Source):
        """Time the query itself, not the wait for a free worker.

        With more sources than threads the later ones sit in the queue, and
        timing from submit would report that queue time as the source being
        slow, which is exactly backwards when picking sources to drop. The
        exception is returned rather than raised so it arrives with its timing.
        """
        source_started = time.time()
        try:
            return source.run(domain), None, time.time() - source_started
        except Exception as exc:  # one broken source must not end the run
            return [], exc, time.time() - source_started

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        future_map = {}
        for source in runnable:
            future = executor.submit(timed, source)
            future_map[future] = source

        for future in concurrent.futures.as_completed(future_map):
            source = future_map[future]
            raw_results, failure, elapsed = future.result()
            if failure is not None:
                # SourceError carries a message written for a human; anything
                # else is a bug in a source and is shown as a repr.
                detail = (_readable(str(failure)) if isinstance(failure, SourceError)
                          else repr(failure))
                stats.append(Stat(source.name, 0, 0, elapsed, error=detail))
                progress("  %s %-16s %s" % (paint("x", "31"), source.name,
                                            paint(detail[:96], "2")))
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
            progress("  %s %-16s %-22s %s"
                     % (paint("+", "32"), source.name, detail,
                        paint("%.1fs" % elapsed, "2")))

    stats.sort(key=lambda stat: stat.name)
    return Findings(domain, hosts, stats, time.time() - started)


def sort_hosts(hosts: Sequence[str]) -> List[str]:
    """Order by label depth then alphabetically, so apex-adjacent names lead."""
    return sorted(hosts, key=lambda host: (host.count("."), host))


# ==========================
# Output
# ==========================


def save_results(domain: str, results: Sequence[str], output_dir: str,
                 stamp: Optional[str] = None) -> str:
    os.makedirs(output_dir, exist_ok=True)

    stamp = stamp or datetime.now().strftime("%Y-%m-%d")
    filename = "%s-subdomains-%s.txt" % (domain, stamp)
    path = os.path.join(output_dir, filename)

    with open(path, "w") as handle:
        for subdomain in sort_hosts(results):
            handle.write(subdomain + "\n")

    return path


def save_json(findings: Findings, output_dir: str,
              stamp: Optional[str] = None) -> str:
    os.makedirs(output_dir, exist_ok=True)

    stamp = stamp or datetime.now().strftime("%Y-%m-%d")
    filename = "%s-subdomains-%s.json" % (findings.domain, stamp)
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
    """Read hostnames from previous runs, for new-asset detection.

    A baseline file that is missing or unreadable is reported and skipped: it
    would otherwise abort the scan, and a shell glob that matches nothing is an
    easy way to hit that (`--known results/*.txt` on the very first run).
    """
    known: Set[str] = set()
    for path in paths:
        try:
            with open(path) as handle:
                for line in handle:
                    host = normalize(line)
                    if is_valid(host):
                        known.add(host)
        except OSError as exc:
            log("[!] Cannot read %s: %s" % (path, exc))
    return known


# ==========================
# Scan
# ==========================


def passive_scan(domain: str, tools: Optional[Sequence[str]], output_dir: str,
                 threads: int = 12, include_all: bool = False, want_json: bool = False,
                 silent: bool = False, show_stats: bool = False,
                 known: Optional[Set[str]] = None, only_new: bool = False,
                 exclude: Optional[Sequence[str]] = None) -> int:
    """Enumerate one domain. Returns the number of hosts reported."""
    domain = normalize(domain)
    if not is_valid(domain):
        log("[!] Invalid domain, skipping")
        return 0

    sources = select_sources(tools, include_all, exclude)
    if not sources:
        log("[!] No sources selected")
        return 0
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

    findings = run_sources(domain, sources, threads, emit, silent)

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
        stamp = datetime.now().strftime("%Y-%m-%d")
        path = save_results(domain, reported, output_dir, stamp)
        if not silent:
            log("   %s %s" % (paint("->", "2"), path))
        if want_json:
            json_path = save_json(findings, output_dir, stamp)
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
    """Print the registry, marking what is ready to run on this machine."""
    print("%-16s %-15s %-7s %s" % ("SOURCE", "AUTH", "STATUS", "NOTES"))
    for source in SOURCES:
        auth = source.provider or ("binary" if source.binary else "none")
        reason = skip_reason(source)
        status = "skip" if reason else "ready"
        notes = source.description
        if not source.default:
            notes += "  [needs --all or --tools]"
        if reason:
            notes += "  (%s)" % reason
        print("%-16s %-15s %-7s %s" % (source.name, auth, status, notes))

    keyless = [s for s in SOURCES if not s.provider and not s.binary]
    ready = [s for s in SOURCES if not skip_reason(s)]
    print("\n%d sources: %d need no credentials and no external tools, "
          "%d ready to run here." % (len(SOURCES), len(keyless), len(ready)))


# ==========================
# Interactive Selection
# ==========================
#
# --interactive opens a checkbox list over the registry, so sources can be
# picked by hand instead of spelled out with -t/-x. It reads and draws on
# /dev/tty rather than the standard streams, which keeps the picker usable
# while hostnames are being piped somewhere and progress is going to stderr.


class NoTerminal(Exception):
    """Raised when there is no terminal the picker can drive."""


_KEYS = {
    "\x1b[A": "up", "\x1b[B": "down", "\x1b[C": "right", "\x1b[D": "left",
    "\x1bOA": "up", "\x1bOB": "down", "\x1bOC": "right", "\x1bOD": "left",
    "\x1b[5~": "pgup", "\x1b[6~": "pgdn",
    "\x1b[H": "home", "\x1b[F": "end", "\x1bOH": "home", "\x1bOF": "end",
    "\x1b[1~": "home", "\x1b[4~": "end", "\x1b[7~": "home", "\x1b[8~": "end",
}

_CONTROL_KEYS = {
    "\r": "enter", "\n": "enter", "\x7f": "backspace", "\b": "backspace",
    "\x03": "ctrl-c", "\x04": "eof", "\x15": "clear",
}


def _utf8_length(first: int) -> int:
    """Total byte length of the UTF-8 character starting with this byte."""
    if first >= 0xF0:
        return 4
    if first >= 0xE0:
        return 3
    if first >= 0xC0:
        return 2
    return 1


def _input_waiting(stream, timeout: float) -> bool:
    import select
    try:
        return bool(select.select([stream], [], [], timeout)[0])
    except (OSError, ValueError):
        # Not a selectable stream (a test double, say): assume the rest of the
        # sequence is already buffered and let the read decide.
        return True


def read_key(stream, waiter: Optional[Callable[[object, float], bool]] = None) -> str:
    """Block for one keypress on a raw-mode byte stream and name it.

    Returns a name for the keys the picker binds ("up", "enter", "esc", ...)
    and the character itself for anything printable.
    """
    waiter = waiter or _input_waiting
    first = stream.read(1)
    if not first:
        return "eof"

    if first != b"\x1b":
        extra = _utf8_length(first[0]) - 1
        raw = first + (stream.read(extra) if extra else b"")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return "unknown"
        return _CONTROL_KEYS.get(text, text)

    # Escape alone means "quit"; escape followed immediately by more bytes is
    # an arrow or navigation key, so wait briefly for the rest of it.
    sequence = first
    while len(sequence) < 8 and waiter(stream, 0.05):
        nxt = stream.read(1)
        if not nxt:
            break
        sequence += nxt
        if sequence.decode("latin-1") in _KEYS:
            break
    text = sequence.decode("latin-1")
    if text in _KEYS:
        return _KEYS[text]
    return "esc" if text == "\x1b" else "unknown"


class SourcePicker:
    """Keyboard-driven checkbox list over the source registry.

    Deliberately a pure state machine: handle_key() updates the selection and
    render() returns the lines to draw. run_picker() supplies the keystrokes
    and paints the result, so everything here is testable without a terminal.
    """

    HELP = ("↑↓ move  ·  space toggle  ·  a all  ·  n none  ·  d defaults  ·  "
            "r ready  ·  / filter  ·  enter run  ·  q quit")

    def __init__(self, sources: Sequence[Source], selected: Sequence[str],
                 reasons: Optional[Dict[str, str]] = None, color: bool = False):
        self.sources = list(sources)
        self.selected = set(selected)
        # Looked up once: skip_reason() shells out to shutil.which().
        self.reasons = dict(reasons) if reasons is not None else {
            source.name: skip_reason(source) for source in self.sources}
        self.color = color
        self.cursor = 0
        self.offset = 0
        self.query = ""
        self.filtering = False
        self.status = ""

    # -- state ------------------------------------------------------------

    def visible(self) -> List[int]:
        """Indexes of the sources matching the current filter, in registry order."""
        if not self.query:
            return list(range(len(self.sources)))
        needle = self.query.lower()
        matched = []
        for index, source in enumerate(self.sources):
            haystack = " ".join((source.name, source.provider, source.binary,
                                 source.description)).lower()
            if needle in haystack:
                matched.append(index)
        return matched

    def result(self) -> List[str]:
        """The chosen source names, in registry order."""
        return [source.name for source in self.sources if source.name in self.selected]

    def handle_key(self, key: str) -> Optional[str]:
        """Apply one keypress. Returns "accept", "cancel", or None to continue."""
        if self.filtering:
            return self._handle_filter_key(key)

        visible = self.visible()
        self.status = ""

        if key in ("up", "k"):
            self._move(-1, visible)
        elif key in ("down", "j"):
            self._move(1, visible)
        elif key == "pgup":
            self._move(-10, visible)
        elif key == "pgdn":
            self._move(10, visible)
        elif key in ("home", "g"):
            self.cursor = 0
        elif key in ("end", "G"):
            self.cursor = max(0, len(visible) - 1)
        elif key in (" ", "x") and visible:
            name = self.sources[visible[min(self.cursor, len(visible) - 1)]].name
            self.selected.symmetric_difference_update({name})
            self._move(1, visible)
        elif key == "a":
            names = {self.sources[index].name for index in visible}
            self.selected |= names
            self.status = "selected %d source(s)" % len(names)
        elif key == "n":
            names = {self.sources[index].name for index in visible}
            self.selected -= names
            self.status = "cleared %d source(s)" % len(names)
        elif key == "d":
            self.selected = {source.name for source in self.sources if source.default}
            self.status = "reset to the default sources"
        elif key == "r":
            names = {self.sources[index].name for index in visible
                     if not self.reasons.get(self.sources[index].name)}
            self.selected |= names
            self.status = "added %d source(s) ready to run here" % len(names)
        elif key == "/":
            self.filtering = True
        elif key == "enter":
            return "accept"
        elif key == "esc" and self.query:
            # A filter is still narrowing the list: clear it rather than
            # quitting, which is what escape means with a filter on screen.
            self.query = ""
            self.cursor = 0
            self.offset = 0
        elif key in ("q", "esc", "ctrl-c", "eof"):
            return "cancel"
        return None

    def _handle_filter_key(self, key: str) -> Optional[str]:
        if key == "enter":
            self.filtering = False
        elif key in ("esc", "ctrl-c"):
            self.filtering = False
            self.query = ""
        elif key == "backspace":
            self.query = self.query[:-1]
        elif key == "clear":
            self.query = ""
        elif key == "eof":
            return "cancel"
        elif len(key) == 1 and key.isprintable():
            self.query += key
        self.cursor = 0
        self.offset = 0
        return None

    def _move(self, delta: int, visible: Sequence[int]) -> None:
        if not visible:
            self.cursor = 0
            return
        self.cursor = max(0, min(self.cursor + delta, len(visible) - 1))

    def _scroll(self, rows: int, total: int) -> None:
        if self.cursor < self.offset:
            self.offset = self.cursor
        elif self.cursor >= self.offset + rows:
            self.offset = self.cursor - rows + 1
        self.offset = max(0, min(self.offset, max(0, total - rows)))

    # -- view -------------------------------------------------------------

    def _paint(self, text: str, code: str) -> str:
        return "\033[%sm%s\033[0m" % (code, text) if self.color else text

    def render(self, width: int = 80, height: int = 24) -> List[str]:
        """Draw the list. Escape codes are applied per row, after truncation."""
        visible = self.visible()
        self.cursor = min(self.cursor, max(0, len(visible) - 1))
        rows = max(1, height - 5)   # two header lines, three at the foot
        self._scroll(rows, len(visible))

        ready = len([name for name in self.selected if not self.reasons.get(name)])
        title = "  sub-passive · select sources"
        tally = "%d selected · %d ready here  " % (len(self.selected), ready)
        gap = max(1, width - len(title) - len(tally))
        lines = [self._paint((title + " " * gap + tally)[:width], "1"), ""]

        for slot in range(rows):
            index = self.offset + slot
            if index >= len(visible):
                lines.append("")
                continue
            source = self.sources[visible[index]]
            reason = self.reasons.get(source.name, "")
            notes = source.description
            if not source.default:
                notes += "  [off by default]"
            if reason:
                notes += "  (%s)" % reason
            row = ("%s %s %-16s %-15s %-7s %s" % (
                ">" if index == self.cursor else " ",
                "[x]" if source.name in self.selected else "[ ]",
                source.name,
                source.provider or ("binary" if source.binary else "none"),
                "skip" if reason else "ready",
                notes,
            ))[:width]
            if index == self.cursor:
                lines.append(self._paint(row.ljust(min(width, 100)), "7"))
            elif reason:
                lines.append(self._paint(row, "2"))
            else:
                lines.append(row)

        lines.append("")
        if self.filtering or self.query:
            footer = "  /%s%s" % (self.query, "_" if self.filtering else "")
            if not visible:
                footer += "   no source matches"
        else:
            footer = "  " + self.status
        lines.append(self._paint(footer[:width], "36"))
        lines.append(self._paint(("  " + self.HELP)[:width], "2"))
        # A frame taller than the terminal would scroll the screen, so on a
        # very short one the help line is what gets cut.
        return lines[:height] if height > 0 else lines


def run_picker(picker: SourcePicker) -> Optional[List[str]]:
    """Drive the picker full-screen on /dev/tty.

    Returns the chosen names, or None if the user quit. Raises NoTerminal when
    this terminal cannot be driven, which is the caller's cue to fall back to
    the numbered prompt.
    """
    try:
        import termios
        import tty
    except ImportError:  # no POSIX terminal control (Windows)
        raise NoTerminal("no terminal control available")

    if os.environ.get("TERM", "") in ("", "dumb"):
        raise NoTerminal("TERM is not set to a usable terminal")

    try:
        stream_in = open("/dev/tty", "rb", buffering=0)
    except OSError as exc:
        raise NoTerminal("cannot open /dev/tty: %s" % exc)
    try:
        stream_out = open("/dev/tty", "w")
    except OSError as exc:
        stream_in.close()
        raise NoTerminal("cannot open /dev/tty: %s" % exc)

    fd = stream_in.fileno()
    try:
        saved = termios.tcgetattr(fd)
    except termios.error as exc:
        stream_in.close()
        stream_out.close()
        raise NoTerminal("cannot read terminal settings: %s" % exc)

    picker.color = not os.environ.get("NO_COLOR")
    try:
        tty.setraw(fd)
        stream_out.write("\033[?1049h\033[?25l")   # alternate screen, hide cursor
        while True:
            size = shutil.get_terminal_size((80, 24))
            frame = picker.render(size.columns, size.lines)
            stream_out.write("\033[H\033[2J" + "\r\n".join(frame))
            stream_out.flush()
            action = picker.handle_key(read_key(stream_in))
            if action == "accept":
                return picker.result()
            if action == "cancel":
                return None
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, saved)
        stream_out.write("\033[?25h\033[?1049l")   # restore cursor and screen
        stream_out.flush()
        stream_in.close()
        stream_out.close()


def toggle_numbers(picker: SourcePicker, text: str) -> List[str]:
    """Toggle sources named by "3" or "5-8" tokens. Returns the bad tokens."""
    bad = []
    for token in text.replace(",", " ").split():
        bounds = token.split("-", 1) if "-" in token[1:] else [token, token]
        try:
            first, last = int(bounds[0]), int(bounds[1])
        except ValueError:
            bad.append(token)
            continue
        if first > last or first < 1 or last > len(picker.sources):
            bad.append(token)
            continue
        for number in range(first, last + 1):
            name = picker.sources[number - 1].name
            picker.selected.symmetric_difference_update({name})
    return bad


def prompt_picker(picker: SourcePicker, read_line: Callable[[], Optional[str]],
                  write: Callable[[str], None]) -> Optional[List[str]]:
    """Numbered fallback for terminals run_picker() cannot drive."""
    while True:
        write("\n%-4s %-3s %-16s %-15s %-7s %s\n"
              % ("#", "ON", "SOURCE", "AUTH", "STATUS", "NOTES"))
        for number, source in enumerate(picker.sources, 1):
            reason = picker.reasons.get(source.name, "")
            notes = source.description
            if reason:
                notes += "  (%s)" % reason
            write("%-4d %-3s %-16s %-15s %-7s %s\n" % (
                number,
                "[x]" if source.name in picker.selected else "[ ]",
                source.name,
                source.provider or ("binary" if source.binary else "none"),
                "skip" if reason else "ready",
                notes,
            ))
        write("\nToggle by number (3, or 5-8) · a all · n none · d defaults · "
              "r ready · q quit\nEnter runs the %d selected source(s) > "
              % len(picker.selected))

        line = read_line()
        if line is None:
            return None
        command = line.strip()
        if not command:
            return picker.result()
        if command.lower() in ("q", "quit"):
            return None
        if command.lower() in ("a", "n", "d", "r"):
            picker.handle_key(command.lower())
            continue
        bad = toggle_numbers(picker, command)
        if bad:
            write("[!] Not a source number: %s\n" % " ".join(bad))


def choose_sources(preset: Sequence[str]) -> Optional[List[str]]:
    """Ask the user which sources to run, starting from the preset selection.

    Returns the chosen names, or None if the user quit. Raises NoTerminal when
    there is no terminal to ask on at all.
    """
    picker = SourcePicker(SOURCES, preset)
    try:
        return run_picker(picker)
    except NoTerminal:
        pass

    handle = None
    try:
        handle = open("/dev/tty", "r+")
        reader, writer = handle, handle
    except OSError:
        if not sys.stdin.isatty():
            raise NoTerminal("no terminal to read a selection from")
        reader, writer = sys.stdin, sys.stderr

    def read_line() -> Optional[str]:
        line = reader.readline()
        return None if line == "" else line

    def write(text: str) -> None:
        writer.write(text)
        writer.flush()

    try:
        return prompt_picker(picker, read_line, write)
    finally:
        if handle is not None:
            handle.close()


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

    parser.add_argument(
        "-x",
        "--exclude",
        nargs="+",
        choices=sorted(TOOLS.keys()),
        default=None,
        metavar="SOURCE",
        help="Sources to skip"
    )

    parser.add_argument("-i", "--interactive", action="store_true",
                        help="Pick sources from a checkbox list before scanning")
    parser.add_argument("--all", action="store_true",
                        help="Also query slow and unreliable sources")
    parser.add_argument("--list-sources", action="store_true",
                        help="List available sources and exit")
    parser.add_argument("--threads", type=int, default=12,
                        help="Sources queried in parallel (default: 12)")
    parser.add_argument("--timeout", type=int, default=None, metavar="SECONDS",
                        help="Override every per-request timeout "
                             "(default: %d, more for the archive sources)"
                             % DEFAULT_TIMEOUT)
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
    global TIMEOUT_OVERRIDE

    args = parse_args()

    if args.list_sources:
        list_sources()
        return

    if args.threads < 1:
        log("[!] --threads must be at least 1")
        sys.exit(1)
    if args.timeout is not None:
        if args.timeout < 1:
            log("[!] --timeout must be at least 1")
            sys.exit(1)
        TIMEOUT_OVERRIDE = args.timeout

    domains = list(args.domain)
    # Accept a list of domains on stdin when none were given on the command line.
    if not domains and not sys.stdin.isatty():
        domains = [line.strip() for line in sys.stdin if line.strip()]
    if not domains:
        log("[!] No target domain given")
        sys.exit(1)

    if args.interactive:
        preset = [source.name for source in
                  select_sources(args.tools, args.all, args.exclude)]
        try:
            chosen = choose_sources(preset)
        except NoTerminal as exc:
            log("[!] --interactive needs a terminal (%s)" % exc)
            sys.exit(1)
        if chosen is None:
            log("[!] Cancelled")
            sys.exit(130)
        if not chosen:
            log("[!] No sources selected")
            sys.exit(1)
        # The picker's answer is the whole selection, so --all and --exclude
        # have already been folded into it.
        args.tools, args.exclude = chosen, None

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
            exclude=args.exclude,
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
