#!/usr/bin/env python3
"""Tests for sub_passive.

Standard library only, to match the tool itself:

    python3 -m unittest discover -s tests -v

Nothing here touches the network. Sources are exercised by stubbing the HTTP
layer, so the tests cover response parsing and pagination without depending on
a third-party service being up.
"""

import io
import json
import os
import sys
import tempfile
import unittest
import urllib.error
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import sub_passive as sp  # noqa: E402


class TestNormalize(unittest.TestCase):
    def test_plain_hostname_is_unchanged(self):
        self.assertEqual(sp.normalize("api.example.com"), "api.example.com")

    def test_case_and_trailing_dot(self):
        self.assertEqual(sp.normalize("  API.Example.COM.  "), "api.example.com")

    def test_strips_scheme_path_and_port(self):
        self.assertEqual(sp.normalize("https://api.example.com:8443/a/b"),
                         "api.example.com")

    def test_strips_wildcards(self):
        self.assertEqual(sp.normalize("*.example.com"), "example.com")
        self.assertEqual(sp.normalize("*.*.example.com"), "example.com")

    def test_protocol_relative(self):
        self.assertEqual(sp.normalize("//cdn.example.com/app.js"),
                         "cdn.example.com")

    def test_userinfo_is_dropped(self):
        self.assertEqual(sp.normalize("http://user:pw@api.example.com/x"),
                         "api.example.com")

    def test_email_address(self):
        self.assertEqual(sp.normalize("security@example.com"), "example.com")

    def test_at_sign_in_query_does_not_hijack_the_host(self):
        """Regression: the path must be cut before userinfo is looked for.

        Archived URLs routinely carry an "@" in a query string. Trimming at
        that "@" first returned the query fragment and silently dropped the
        real host, losing hosts from every URL-shaped source.
        """
        self.assertEqual(
            sp.normalize("https://example.com/redirect?to=user@cdn.other.com"),
            "example.com")
        self.assertEqual(sp.normalize("https://example.com/p?x=a@b"),
                         "example.com")
        self.assertEqual(sp.normalize("https://example.com/a#frag@z"),
                         "example.com")

    def test_empty_input(self):
        self.assertEqual(sp.normalize(""), "")
        self.assertEqual(sp.normalize("   "), "")

    def test_non_strings_normalize_to_empty(self):
        """One stray null in a JSON list must not cost the whole source."""
        for value in (None, 1, 1.5, True, [], {}):
            self.assertEqual(sp.normalize(value), "")

    def test_quotes_and_punctuation(self):
        self.assertEqual(sp.normalize('"api.example.com",'), "api.example.com")


class TestIsValid(unittest.TestCase):
    def test_accepts_ordinary_hostnames(self):
        for host in ("example.com", "a.b.c.example.com", "x-1.example.com"):
            self.assertTrue(sp.is_valid(host), host)

    def test_accepts_underscore_service_records(self):
        self.assertTrue(sp.is_valid("_dmarc.example.com"))

    def test_rejects_single_label(self):
        self.assertFalse(sp.is_valid("localhost"))

    def test_rejects_empty_and_double_dot(self):
        self.assertFalse(sp.is_valid(""))
        self.assertFalse(sp.is_valid("a..b.com"))

    def test_rejects_ip_addresses(self):
        self.assertFalse(sp.is_valid("192.168.1.1"))

    def test_rejects_leading_or_trailing_hyphen(self):
        self.assertFalse(sp.is_valid("-bad.example.com"))
        self.assertFalse(sp.is_valid("bad-.example.com"))

    def test_rejects_overlong_names(self):
        self.assertFalse(sp.is_valid("a" * 64 + ".example.com"))
        self.assertFalse(sp.is_valid(("a." * 130) + "example.com"))


class TestInScope(unittest.TestCase):
    def test_apex_and_subdomains(self):
        self.assertTrue(sp.in_scope("example.com", "example.com"))
        self.assertTrue(sp.in_scope("a.b.example.com", "example.com"))

    def test_rejects_suffix_lookalikes(self):
        self.assertFalse(sp.in_scope("notexample.com", "example.com"))

    def test_rejects_prefix_lookalikes(self):
        self.assertFalse(sp.in_scope("example.com.attacker.net", "example.com"))


class TestExtractHosts(unittest.TestCase):
    def test_mines_hosts_out_of_html(self):
        html = '<a href="https://api.example.com/v1">api</a> mail.example.com'
        self.assertEqual(sorted(sp.extract_hosts(html, "example.com")),
                         ["api.example.com", "mail.example.com"])

    def test_deduplicates_preserving_order(self):
        text = "a.example.com b.example.com a.example.com"
        self.assertEqual(sp.extract_hosts(text, "example.com"),
                         ["a.example.com", "b.example.com"])

    def test_rejects_lookalike_domains(self):
        # Greedy tokenizing must capture the whole name so in_scope() can
        # reject it, rather than yielding a bogus "example.com".
        text = "example.com.attacker.net and notexample.com"
        self.assertEqual(sp.extract_hosts(text, "example.com"), [])

    def test_out_of_scope_hosts_are_dropped(self):
        text = "cdn.cloudflare.com api.example.com"
        self.assertEqual(sp.extract_hosts(text, "example.com"),
                         ["api.example.com"])


class TestJsonStrings(unittest.TestCase):
    def test_walks_nested_structures(self):
        payload = {"a": ["x", {"b": "y"}], "c": {"d": ["z"]}}
        self.assertEqual(sorted(sp.json_strings(payload)), ["x", "y", "z"])

    def test_ignores_non_strings(self):
        self.assertEqual(sp.json_strings({"n": 1, "f": 1.5, "b": True,
                                          "none": None, "s": "keep"}),
                         ["keep"])

    def test_handles_scalars_and_empties(self):
        self.assertEqual(sp.json_strings([]), [])
        self.assertEqual(sp.json_strings("bare"), ["bare"])


class TestReadBody(unittest.TestCase):
    """The HTTP layer asks for gzip, so it has to be able to undo it."""

    class FakeResponse:
        def __init__(self, body, encoding=""):
            self.body = body
            self.headers = {"Content-Encoding": encoding} if encoding else {}

        def read(self):
            return self.body

    def test_identity(self):
        self.assertEqual(sp._read_body(self.FakeResponse(b"hello")), "hello")

    def test_gzip(self):
        import gzip
        payload = gzip.compress(b"a.example.com")
        self.assertEqual(
            sp._read_body(self.FakeResponse(payload, "gzip")), "a.example.com")

    def test_deflate(self):
        import zlib
        payload = zlib.compress(b"b.example.com")
        self.assertEqual(
            sp._read_body(self.FakeResponse(payload, "deflate")), "b.example.com")

    def test_raw_deflate_without_zlib_header(self):
        import zlib
        compressor = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
        payload = compressor.compress(b"c.example.com") + compressor.flush()
        self.assertEqual(
            sp._read_body(self.FakeResponse(payload, "deflate")), "c.example.com")

    def test_undecodable_bytes_do_not_raise(self):
        self.assertIn("example.com",
                      sp._read_body(self.FakeResponse(b"\xff\xfeexample.com")))

    def test_corrupt_gzip_is_a_source_error(self):
        with self.assertRaises(sp.SourceError):
            sp._read_body(self.FakeResponse(b"not actually gzip", "gzip"))


class TestTimeoutResolution(unittest.TestCase):
    """--timeout has to reach the sources that set their own longer values."""

    def _captured_timeout(self, override, per_source):
        seen = {}

        def fake_urlopen(request, timeout=None):
            seen["timeout"] = timeout
            raise urllib.error.URLError("stop here")

        with mock.patch.object(sp, "TIMEOUT_OVERRIDE", override):
            with mock.patch.object(sp.urllib.request, "urlopen", fake_urlopen):
                with self.assertRaises(sp.SourceError):
                    sp.http_get("https://example.invalid", timeout=per_source,
                                retries=0)
        return seen["timeout"]

    def test_default_is_used_when_nothing_is_specified(self):
        self.assertEqual(self._captured_timeout(None, None),
                         sp.DEFAULT_TIMEOUT)

    def test_a_source_may_ask_for_longer(self):
        self.assertEqual(self._captured_timeout(None, 180), 180)

    def test_the_override_beats_a_longer_per_source_value(self):
        self.assertEqual(self._captured_timeout(5, 180), 5)

    def test_the_override_beats_the_default(self):
        self.assertEqual(self._captured_timeout(5, None), 5)


class TestApiKey(unittest.TestCase):
    def test_missing_key_is_none(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(sp.api_key("virustotal"))

    def test_empty_key_is_none(self):
        with mock.patch.dict(os.environ, {"SUB_PASSIVE_VIRUSTOTAL_KEY": ""}):
            self.assertIsNone(sp.api_key("virustotal"))

    def test_key_is_read_from_the_environment(self):
        with mock.patch.dict(os.environ, {"SUB_PASSIVE_VIRUSTOTAL_KEY": "abc"}):
            self.assertEqual(sp.api_key("virustotal"), "abc")


class TestSources(unittest.TestCase):
    """Response parsing per source, with the HTTP layer stubbed out."""

    def test_crtsh_reads_common_name_and_sans(self):
        payload = json.dumps([
            {"common_name": "a.example.com",
             "name_value": "b.example.com\n*.c.example.com"},
            {"common_name": "", "name_value": "d.example.com"},
        ])
        with mock.patch.object(sp, "http_get", return_value=payload):
            hosts = sp.crtsh("example.com")
        self.assertIn("a.example.com", hosts)
        self.assertIn("b.example.com", hosts)
        self.assertIn("*.c.example.com", hosts)
        self.assertIn("d.example.com", hosts)

    def test_hackertarget_takes_the_first_csv_column(self):
        body = "a.example.com,1.2.3.4\nb.example.com,5.6.7.8\n"
        with mock.patch.object(sp, "http_get", return_value=body):
            self.assertEqual(sp.hackertarget("example.com"),
                             ["a.example.com", "b.example.com"])

    def test_hackertarget_reports_quota_exhaustion(self):
        with mock.patch.object(sp, "http_get",
                               return_value="API count exceeded - ..."):
            with self.assertRaises(sp.SourceError):
                sp.hackertarget("example.com")

    def test_subdomaincenter_rejects_a_non_list_payload(self):
        """An error object would otherwise be iterated as if it were hosts."""
        with mock.patch.object(sp, "http_get", return_value='{"error": "nope"}'):
            with self.assertRaises(sp.SourceError):
                sp.subdomain_center("example.com")

    def test_subdomaincenter_passes_a_list_through(self):
        with mock.patch.object(sp, "http_get",
                               return_value='["a.example.com"]'):
            self.assertEqual(sp.subdomain_center("example.com"),
                             ["a.example.com"])

    def test_certspotter_paginates_only_with_a_key(self):
        pages = [
            json.dumps([{"id": "1", "dns_names": ["a.example.com"]}]),
            json.dumps([{"id": "2", "dns_names": ["b.example.com"]}]),
            json.dumps([]),
        ]
        with mock.patch.dict(os.environ,
                             {"SUB_PASSIVE_CERTSPOTTER_KEY": "k"}):
            with mock.patch.object(sp, "http_get", side_effect=pages) as get:
                hosts = sp.certspotter("example.com")
        self.assertEqual(hosts, ["a.example.com", "b.example.com"])
        self.assertEqual(get.call_count, 3)

    def test_certspotter_anonymous_fetches_one_page(self):
        payload = json.dumps([{"id": "1", "dns_names": ["a.example.com"]}])
        with mock.patch.dict(os.environ, {}, clear=True):
            with mock.patch.object(sp, "http_get",
                                   return_value=payload) as get:
                hosts = sp.certspotter("example.com")
        self.assertEqual(hosts, ["a.example.com"])
        self.assertEqual(get.call_count, 1)

    def test_certspotter_keeps_earlier_pages_when_a_later_one_fails(self):
        outcomes = [json.dumps([{"id": "1", "dns_names": ["a.example.com"]}]),
                    sp.SourceError("rate limited")]
        with mock.patch.dict(os.environ,
                             {"SUB_PASSIVE_CERTSPOTTER_KEY": "k"}):
            with mock.patch.object(sp, "http_get", side_effect=outcomes):
                self.assertEqual(sp.certspotter("example.com"),
                                 ["a.example.com"])

    def test_certspotter_first_page_failure_propagates(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with mock.patch.object(sp, "http_get",
                                   side_effect=sp.SourceError("down")):
                with self.assertRaises(sp.SourceError):
                    sp.certspotter("example.com")

    def test_securitytrails_expands_relative_labels(self):
        payload = json.dumps({"subdomains": ["api", "www"]})
        with mock.patch.dict(os.environ,
                             {"SUB_PASSIVE_SECURITYTRAILS_KEY": "k"}):
            with mock.patch.object(sp, "http_get", return_value=payload):
                self.assertEqual(sp.securitytrails("example.com"),
                                 ["api.example.com", "www.example.com"])

    def test_chaos_handles_the_empty_label(self):
        payload = json.dumps({"subdomains": ["api", ""]})
        with mock.patch.dict(os.environ, {"SUB_PASSIVE_CHAOS_KEY": "k"}):
            with mock.patch.object(sp, "http_get", return_value=payload):
                self.assertEqual(sp.chaos("example.com"),
                                 ["api.example.com", "example.com"])

    def test_shodan_merges_subdomains_and_records(self):
        payload = json.dumps({"subdomains": ["api"],
                              "data": [{"subdomain": "mail"},
                                       {"subdomain": ""}]})
        with mock.patch.dict(os.environ, {"SUB_PASSIVE_SHODAN_KEY": "k"}):
            with mock.patch.object(sp, "http_get", return_value=payload):
                self.assertEqual(sp.shodan("example.com"),
                                 ["api.example.com", "mail.example.com",
                                  "example.com"])

    def test_fullhunt_reads_hosts(self):
        payload = json.dumps({"hosts": ["a.example.com"]})
        with mock.patch.dict(os.environ, {"SUB_PASSIVE_FULLHUNT_KEY": "k"}):
            with mock.patch.object(sp, "http_get", return_value=payload):
                self.assertEqual(sp.fullhunt("example.com"), ["a.example.com"])

    def test_fullhunt_tolerates_a_missing_field(self):
        with mock.patch.dict(os.environ, {"SUB_PASSIVE_FULLHUNT_KEY": "k"}):
            with mock.patch.object(sp, "http_get", return_value="{}"):
                self.assertEqual(sp.fullhunt("example.com"), [])

    def test_bevigil_reads_subdomains(self):
        payload = json.dumps({"subdomains": ["a.example.com"]})
        with mock.patch.dict(os.environ, {"SUB_PASSIVE_BEVIGIL_KEY": "k"}):
            with mock.patch.object(sp, "http_get", return_value=payload):
                self.assertEqual(sp.bevigil("example.com"), ["a.example.com"])

    def test_dnsdumpster_harvests_every_section(self):
        payload = json.dumps({"a": [{"host": "a.example.com"}],
                              "cname": [{"host": "c.example.com"}],
                              "ns": [{"host": "ns.example.com"}]})
        with mock.patch.dict(os.environ, {"SUB_PASSIVE_DNSDUMPSTER_KEY": "k"}):
            with mock.patch.object(sp, "http_get", return_value=payload):
                hosts = sp.dnsdumpster("example.com")
        self.assertEqual(sorted(hosts),
                         ["a.example.com", "c.example.com", "ns.example.com"])

    def test_leakix_harvests_nested_records(self):
        payload = json.dumps([{"subdomain": "a.example.com",
                               "distinct_ips": 2}])
        with mock.patch.dict(os.environ, {"SUB_PASSIVE_LEAKIX_KEY": "k"}):
            with mock.patch.object(sp, "http_get", return_value=payload):
                self.assertEqual(sp.leakix("example.com"), ["a.example.com"])

    def test_whoisxmlapi_reads_the_result_block(self):
        payload = json.dumps({"result": {"records": [
            {"domain": "a.example.com"}]}})
        with mock.patch.dict(os.environ, {"SUB_PASSIVE_WHOISXMLAPI_KEY": "k"}):
            with mock.patch.object(sp, "http_get", return_value=payload):
                self.assertEqual(sp.whoisxmlapi("example.com"),
                                 ["a.example.com"])

    def test_netlas_stops_on_an_empty_page(self):
        pages = [json.dumps({"items": [{"data": {"domain": "a.example.com"}}]}),
                 json.dumps({"items": []})]
        with mock.patch.dict(os.environ, {"SUB_PASSIVE_NETLAS_KEY": "k"}):
            with mock.patch.object(sp, "http_get", side_effect=pages) as get:
                hosts = sp.netlas("example.com")
        self.assertEqual(hosts, ["a.example.com"])
        self.assertEqual(get.call_count, 2)

    def test_hudsonrock_harvests_urls(self):
        payload = json.dumps({"data": {"employees_urls": [
            {"url": "https://intranet.example.com/login"}]}})
        with mock.patch.object(sp, "http_get", return_value=payload):
            self.assertIn("https://intranet.example.com/login",
                          sp.hudsonrock("example.com"))

    def test_alienvault_reads_passive_dns(self):
        payload = json.dumps({"passive_dns": [{"hostname": "a.example.com"}]})
        with mock.patch.dict(os.environ, {"SUB_PASSIVE_ALIENVAULT_KEY": "k"}):
            with mock.patch.object(sp, "http_get", return_value=payload):
                self.assertEqual(sp.alienvault("example.com"),
                                 ["a.example.com"])

    def test_virustotal_follows_the_next_link(self):
        pages = [
            json.dumps({"data": [{"id": "a.example.com"}],
                        "links": {"next": "https://next"}}),
            json.dumps({"data": [{"id": "b.example.com"}], "links": {}}),
        ]
        with mock.patch.dict(os.environ, {"SUB_PASSIVE_VIRUSTOTAL_KEY": "k"}):
            with mock.patch.object(sp, "http_get", side_effect=pages):
                self.assertEqual(sp.virustotal("example.com"),
                                 ["a.example.com", "b.example.com"])

    def test_http_json_rejects_a_non_json_body(self):
        with mock.patch.object(sp, "http_get", return_value="<html>502</html>"):
            with self.assertRaises(sp.SourceError):
                sp.http_json("https://example.invalid")


class TestExternalTools(unittest.TestCase):
    def test_run_tool_reads_bare_hostname_output(self):
        with mock.patch.object(sp, "run_command",
                               return_value=["a.example.com", "b.example.com"]):
            self.assertEqual(sp.subfinder("example.com"),
                             ["a.example.com", "b.example.com"])

    def test_run_tool_reads_url_output(self):
        with mock.patch.object(
                sp, "run_command",
                return_value=["https://a.example.com/x?q=1",
                              "https://b.example.com/y"]):
            self.assertEqual(sp.waymore("example.com"),
                             ["a.example.com", "b.example.com"])

    def test_run_tool_reads_amass_record_output(self):
        """amass prints "host (FQDN) --> record --> value", not bare names."""
        with mock.patch.object(
                sp, "run_command",
                return_value=["a.example.com (FQDN) --> a_record --> 1.2.3.4"]):
            self.assertEqual(sp.amass("example.com"), ["a.example.com"])

    def test_run_tool_drops_out_of_scope_output(self):
        with mock.patch.object(
                sp, "run_command",
                return_value=["a.example.com", "cdn.othersite.net"]):
            self.assertEqual(sp.gau("example.com"), ["a.example.com"])

    def test_run_command_keeps_output_from_a_nonzero_exit(self):
        completed = mock.Mock(returncode=1, stdout="a.example.com\n", stderr="")
        with mock.patch.object(sp.subprocess, "run", return_value=completed):
            self.assertEqual(sp.run_command(["x"]), ["a.example.com"])

    def test_run_command_raises_when_it_fails_silently(self):
        completed = mock.Mock(returncode=1, stdout="", stderr="boom")
        with mock.patch.object(sp.subprocess, "run", return_value=completed):
            with self.assertRaises(sp.SourceError):
                sp.run_command(["x"])

    def test_run_command_reports_a_timeout(self):
        with mock.patch.object(
                sp.subprocess, "run",
                side_effect=sp.subprocess.TimeoutExpired("x", 1)):
            with self.assertRaises(sp.SourceError):
                sp.run_command(["x"])

    def test_run_command_reports_a_missing_binary(self):
        with mock.patch.object(sp.subprocess, "run",
                               side_effect=OSError("No such file")):
            with self.assertRaises(sp.SourceError):
                sp.run_command(["x"])


class TestRegistry(unittest.TestCase):
    def test_names_are_unique(self):
        names = [source.name for source in sp.SOURCES]
        self.assertEqual(len(names), len(set(names)))

    def test_lookup_table_matches_the_registry(self):
        self.assertEqual(len(sp.SOURCES_BY_NAME), len(sp.SOURCES))
        self.assertEqual(set(sp.TOOLS), set(sp.SOURCES_BY_NAME))

    def test_the_three_original_tool_names_still_resolve(self):
        for name in ("subfinder", "assetfinder", "waymore"):
            self.assertIn(name, sp.SOURCES_BY_NAME)

    def test_every_source_is_callable(self):
        for source in sp.SOURCES:
            self.assertTrue(callable(source.run), source.name)

    def test_a_source_declares_at_most_one_requirement(self):
        for source in sp.SOURCES:
            self.assertFalse(source.binary and source.provider, source.name)

    def test_keyless_defaults_need_no_setup(self):
        for source in sp.SOURCES:
            if source.default and not source.binary and not source.provider:
                self.assertEqual(sp.skip_reason(source), "", source.name)


class TestSelectSources(unittest.TestCase):
    def test_default_excludes_opt_in_sources(self):
        names = [s.name for s in sp.select_sources(None, False)]
        self.assertIn("crtsh", names)
        self.assertNotIn("commoncrawl", names)

    def test_all_includes_opt_in_sources(self):
        names = [s.name for s in sp.select_sources(None, True)]
        self.assertIn("commoncrawl", names)

    def test_explicit_names_win_over_defaults(self):
        names = [s.name for s in sp.select_sources(["commoncrawl"], False)]
        self.assertEqual(names, ["commoncrawl"])

    def test_duplicate_names_are_collapsed(self):
        names = [s.name for s in sp.select_sources(["crtsh", "crtsh"], False)]
        self.assertEqual(names, ["crtsh"])

    def test_registry_order_is_preserved(self):
        names = [s.name for s in sp.select_sources(["wayback", "crtsh"], False)]
        self.assertEqual(names, ["crtsh", "wayback"])

    def test_unknown_name_is_rejected(self):
        with self.assertRaises(ValueError):
            sp.select_sources(["nope"], False)

    def test_exclude_removes_a_default(self):
        names = [s.name for s in sp.select_sources(None, False,
                                                   exclude=["crtsh"])]
        self.assertNotIn("crtsh", names)

    def test_exclude_applies_to_explicit_names_too(self):
        names = [s.name for s in sp.select_sources(["crtsh", "wayback"], False,
                                                   exclude=["crtsh"])]
        self.assertEqual(names, ["wayback"])


class TestSkipReason(unittest.TestCase):
    def test_missing_binary(self):
        source = sp.SOURCES_BY_NAME["subfinder"]
        with mock.patch.object(sp, "is_tool_installed", return_value=False):
            self.assertEqual(sp.skip_reason(source), "not installed")

    def test_present_binary(self):
        source = sp.SOURCES_BY_NAME["subfinder"]
        with mock.patch.object(sp, "is_tool_installed", return_value=True):
            self.assertEqual(sp.skip_reason(source), "")

    def test_missing_key_names_the_variable(self):
        source = sp.SOURCES_BY_NAME["virustotal"]
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(sp.skip_reason(source),
                             "no SUB_PASSIVE_VIRUSTOTAL_KEY")

    def test_present_key(self):
        source = sp.SOURCES_BY_NAME["virustotal"]
        with mock.patch.dict(os.environ,
                             {"SUB_PASSIVE_VIRUSTOTAL_KEY": "k"}):
            self.assertEqual(sp.skip_reason(source), "")


class QuietTestCase(unittest.TestCase):
    """Base class that keeps a test's own progress output off the console.

    run_sources() and passive_scan() log to stderr and stream hosts to stdout by
    design; both are silenced here so the test report stays readable.
    """

    def setUp(self):
        super().setUp()
        for patcher in (mock.patch.object(sp, "log"),
                        mock.patch.object(sys, "stdout", io.StringIO())):
            patcher.start()
            self.addCleanup(patcher.stop)


class TestRunSources(QuietTestCase):
    @staticmethod
    def _source(name, run, **kwargs):
        return sp.Source(name, run, name, **kwargs)

    @staticmethod
    def _raise(domain):
        raise sp.SourceError("down")

    def test_merges_and_deduplicates_across_sources(self):
        sources = [
            self._source("one", lambda d: ["a.example.com", "b.example.com"]),
            self._source("two", lambda d: ["b.example.com", "c.example.com"]),
        ]
        findings = sp.run_sources("example.com", sources, 2, lambda h: None)
        self.assertEqual(sorted(findings.hosts),
                         ["a.example.com", "b.example.com", "c.example.com"])
        self.assertEqual(sorted(findings.hosts["b.example.com"]), ["one", "two"])

    def test_out_of_scope_and_invalid_results_are_dropped(self):
        sources = [self._source(
            "one", lambda d: ["a.example.com", "evil.net", "1.2.3.4", "",
                              None, 7, "example.com.attacker.net"])]
        findings = sp.run_sources("example.com", sources, 1, lambda h: None)
        self.assertEqual(list(findings.hosts), ["a.example.com"])

    def test_a_failing_source_does_not_end_the_run(self):
        def boom(domain):
            raise sp.SourceError("rate limited")

        sources = [self._source("bad", boom),
                   self._source("good", lambda d: ["a.example.com"])]
        findings = sp.run_sources("example.com", sources, 2, lambda h: None)
        self.assertEqual(list(findings.hosts), ["a.example.com"])
        errors = {s.name: s.error for s in findings.stats if s.error}
        self.assertIn("bad", errors)

    def test_an_unexpected_exception_is_contained(self):
        def boom(domain):
            raise ValueError("bug in a source")

        sources = [self._source("bad", boom),
                   self._source("good", lambda d: ["a.example.com"])]
        findings = sp.run_sources("example.com", sources, 2, lambda h: None)
        self.assertEqual(list(findings.hosts), ["a.example.com"])
        self.assertTrue(any(s.error for s in findings.stats))

    def test_skipped_sources_are_recorded_and_never_run(self):
        called = []

        def should_not_run(domain):
            called.append(domain)
            return []

        source = self._source("keyed", should_not_run, provider="nosuchprovider")
        with mock.patch.dict(os.environ, {}, clear=True):
            findings = sp.run_sources("example.com", [source], 2,
                                      lambda h: None)
        self.assertEqual(called, [])
        self.assertEqual(len(findings.stats), 1)
        self.assertTrue(findings.stats[0].skipped)

    def test_emit_fires_once_per_new_host(self):
        emitted = []
        sources = [
            self._source("one", lambda d: ["a.example.com", "a.example.com"]),
            self._source("two", lambda d: ["a.example.com", "b.example.com"]),
        ]
        sp.run_sources("example.com", sources, 1, emitted.append)
        self.assertEqual(sorted(emitted), ["a.example.com", "b.example.com"])

    def test_stats_count_found_and_unique_separately(self):
        sources = [
            self._source("one", lambda d: ["a.example.com"]),
            self._source("two", lambda d: ["a.example.com", "b.example.com"]),
        ]
        findings = sp.run_sources("example.com", sources, 1, lambda h: None)
        stats = {s.name: s for s in findings.stats}
        self.assertEqual(stats["one"].found, 1)
        self.assertEqual(stats["one"].unique, 1)
        self.assertEqual(stats["two"].found, 2)
        self.assertEqual(stats["two"].unique, 1)

    def test_silent_suppresses_progress_logging(self):
        """--silent promises hostnames and nothing else, on either stream."""
        sources = [self._source("one", lambda d: ["a.example.com"]),
                   self._source("bad", self._raise)]
        with mock.patch.object(sp, "log") as logged:
            sp.run_sources("example.com", sources, 2, lambda h: None,
                           silent=True)
        self.assertFalse(logged.called)

    def test_progress_is_logged_when_not_silent(self):
        sources = [self._source("one", lambda d: ["a.example.com"])]
        with mock.patch.object(sp, "log") as logged:
            sp.run_sources("example.com", sources, 1, lambda h: None)
        self.assertTrue(logged.called)

    def test_no_runnable_sources_yields_an_empty_result(self):
        findings = sp.run_sources("example.com", [], 4, lambda h: None)
        self.assertEqual(findings.hosts, {})
        self.assertEqual(findings.stats, [])


class TestSortHosts(unittest.TestCase):
    def test_shallow_names_come_first(self):
        hosts = ["c.b.a.example.com", "example.com", "b.example.com",
                 "a.example.com"]
        self.assertEqual(sp.sort_hosts(hosts),
                         ["example.com", "a.example.com", "b.example.com",
                          "c.b.a.example.com"])


class TestOutput(unittest.TestCase):
    def test_save_results_writes_sorted_hosts(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = sp.save_results("example.com",
                                   ["b.example.com", "example.com"], tmp)
            with open(path) as handle:
                self.assertEqual(handle.read().split(),
                                 ["example.com", "b.example.com"])

    def test_save_results_creates_the_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            nested = os.path.join(tmp, "a", "b")
            path = sp.save_results("example.com", ["example.com"], nested)
            self.assertTrue(os.path.exists(path))

    def test_the_filename_format_is_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = sp.save_results("example.com", ["example.com"], tmp,
                                   stamp="2026-01-02")
            self.assertEqual(os.path.basename(path),
                             "example.com-subdomains-2026-01-02.txt")

    def test_save_json_reports_hosts_sources_and_summary(self):
        findings = sp.Findings(
            "example.com",
            {"a.example.com": ["crtsh"], "example.com": ["crtsh", "wayback"]},
            [sp.Stat("crtsh", 2, 2, 1.0),
             sp.Stat("wayback", 1, 0, 2.0, error="http 503"),
             sp.Stat("shodan", 0, 0, 0.0, skipped="no key")],
            3.0)
        with tempfile.TemporaryDirectory() as tmp:
            path = sp.save_json(findings, tmp, stamp="2026-01-02")
            self.assertEqual(os.path.basename(path),
                             "example.com-subdomains-2026-01-02.json")
            with open(path) as handle:
                report = json.load(handle)

        self.assertEqual(report["domain"], "example.com")
        self.assertEqual(report["version"], sp.VERSION)
        self.assertEqual(report["summary"]["hosts"], 2)
        self.assertEqual(report["summary"]["sources_queried"], 2)
        self.assertEqual(report["summary"]["sources_failed"], 1)
        # Sorted apex first, and each host carries the sources that saw it.
        self.assertEqual([h["host"] for h in report["hosts"]],
                         ["example.com", "a.example.com"])
        self.assertEqual(report["hosts"][0]["sources"], ["crtsh", "wayback"])


class TestLoadKnown(unittest.TestCase):
    def test_reads_and_normalizes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "known.txt")
            with open(path, "w") as handle:
                handle.write("A.Example.com\nhttps://b.example.com/x\n\nbad\n")
            self.assertEqual(sp.load_known([path]),
                             {"a.example.com", "b.example.com"})

    def test_a_missing_file_is_reported_not_fatal(self):
        """A --known glob that matches nothing must not abort the scan."""
        with mock.patch.object(sp, "log") as logged:
            self.assertEqual(sp.load_known(["/nonexistent/known.txt"]), set())
        self.assertTrue(logged.called)

    def test_reads_several_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = os.path.join(tmp, "a.txt")
            second = os.path.join(tmp, "b.txt")
            with open(first, "w") as handle:
                handle.write("a.example.com\n")
            with open(second, "w") as handle:
                handle.write("b.example.com\n")
            self.assertEqual(sp.load_known([first, second]),
                             {"a.example.com", "b.example.com"})


class TestPassiveScan(QuietTestCase):
    def _run(self, tmp, **kwargs):
        return sp.passive_scan("example.com", ["crtsh"], tmp, threads=1,
                               silent=True, **kwargs)

    def test_writes_a_file_and_counts_hosts(self):
        payload = json.dumps([{"common_name": "a.example.com",
                               "name_value": "b.example.com"}])
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(sp, "http_get", return_value=payload):
                count = self._run(tmp)
            written = os.listdir(tmp)
        self.assertEqual(count, 2)
        self.assertEqual(len(written), 1)

    def test_no_results_writes_no_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(sp, "http_get", return_value="[]"):
                count = self._run(tmp)
            self.assertEqual(os.listdir(tmp), [])
        self.assertEqual(count, 0)

    def test_json_report_is_written_alongside(self):
        payload = json.dumps([{"common_name": "a.example.com",
                               "name_value": ""}])
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(sp, "http_get", return_value=payload):
                self._run(tmp, want_json=True)
            self.assertEqual(len(os.listdir(tmp)), 2)

    def test_only_new_filters_against_the_baseline(self):
        payload = json.dumps([{"common_name": "a.example.com",
                               "name_value": "b.example.com"}])
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(sp, "http_get", return_value=payload):
                count = self._run(tmp, known={"a.example.com"}, only_new=True)
            name = os.listdir(tmp)[0]
            with open(os.path.join(tmp, name)) as handle:
                self.assertEqual(handle.read().split(), ["b.example.com"])
        self.assertEqual(count, 1)

    def test_an_invalid_domain_is_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(
                sp.passive_scan("not a domain", ["crtsh"], tmp, silent=True), 0)
            self.assertEqual(os.listdir(tmp), [])

    def test_the_domain_is_normalized_before_use(self):
        payload = json.dumps([{"common_name": "a.example.com",
                               "name_value": ""}])
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(sp, "http_get", return_value=payload):
                sp.passive_scan("HTTPS://Example.com/path", ["crtsh"], tmp,
                                threads=1, silent=True)
            self.assertTrue(os.listdir(tmp)[0].startswith("example.com-"))

    def test_excluding_every_source_reports_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            count = sp.passive_scan("example.com", ["crtsh"], tmp,
                                    silent=True, exclude=["crtsh"])
        self.assertEqual(count, 0)


class TestCli(unittest.TestCase):
    def _parse(self, argv):
        with mock.patch.object(sys, "argv", ["sub_passive.py"] + argv):
            return sp.parse_args()

    def test_defaults(self):
        args = self._parse(["example.com"])
        self.assertEqual(args.domain, ["example.com"])
        self.assertIsNone(args.tools)
        self.assertEqual(args.threads, 12)
        self.assertEqual(args.output_dir, ".")

    def test_original_flags_still_parse(self):
        args = self._parse(["example.com", "-o", "out",
                            "-t", "subfinder", "assetfinder", "waymore"])
        self.assertEqual(args.output_dir, "out")
        self.assertEqual(args.tools, ["subfinder", "assetfinder", "waymore"])

    def test_several_domains(self):
        self.assertEqual(self._parse(["a.com", "b.com"]).domain,
                         ["a.com", "b.com"])

    def test_exclude_parses(self):
        self.assertEqual(self._parse(["a.com", "-x", "wayback"]).exclude,
                         ["wayback"])

    def test_an_unknown_source_is_rejected(self):
        with mock.patch.object(sys, "stderr", io.StringIO()):
            with self.assertRaises(SystemExit):
                self._parse(["a.com", "-t", "nosuchsource"])

    def test_list_sources_runs(self):
        with mock.patch.object(sys, "stdout", io.StringIO()) as out:
            sp.list_sources()
        printed = out.getvalue()
        for name in ("crtsh", "subfinder", "SOURCE"):
            self.assertIn(name, printed)


if __name__ == "__main__":
    unittest.main()
