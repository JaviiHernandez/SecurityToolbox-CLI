"""Unit tests for scope validation."""

import pytest

from stbox.scope import ScopeError, check_target, extract_host, is_private_ip


class TestScope:
    def test_accepts_https_url(self):
        normalized, notes = check_target("https://example.com")
        assert normalized == "https://example.com"
        assert notes == []

    def test_normalizes_bare_host(self):
        normalized, _ = check_target("example.com")
        assert normalized == "https://example.com"

    def test_rejects_mil_tld(self):
        with pytest.raises(ScopeError, match="hard-block"):
            check_target("https://example.mil")

    def test_rejects_gov_tld(self):
        with pytest.raises(ScopeError, match="hard-block"):
            check_target("https://whitehouse.gov")

    def test_rejects_gob_tld(self):
        with pytest.raises(ScopeError, match="hard-block"):
            check_target("https://ejemplo.gob.es")

    def test_rejects_rfc1918_without_flag(self):
        with pytest.raises(ScopeError, match="internal"):
            check_target("https://192.168.1.1")

    def test_accepts_rfc1918_with_flag(self):
        normalized, notes = check_target(
            "https://192.168.1.1", allow_internal=True
        )
        assert normalized == "https://192.168.1.1"
        assert any("internal" in n for n in notes)

    def test_rejects_loopback(self):
        with pytest.raises(ScopeError, match="internal"):
            check_target("https://127.0.0.1")

    def test_rejects_aws_console(self):
        with pytest.raises(ScopeError, match="SaaS"):
            check_target("https://console.aws.amazon.com")

    def test_warns_on_edu(self):
        _, notes = check_target("https://university.edu")
        assert any("authorization" in n for n in notes)


class TestIsPrivateIp:
    @pytest.mark.parametrize(
        "ip",
        ["127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1", "::1", "fe80::1"],
    )
    def test_private(self, ip):
        assert is_private_ip(ip)

    @pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "93.184.216.34"])
    def test_public(self, ip):
        assert not is_private_ip(ip)

    def test_not_an_ip(self):
        assert not is_private_ip("example.com")


class TestExtractHost:
    def test_with_port(self):
        assert extract_host("https://example.com:8080") == "example.com"

    def test_no_scheme(self):
        assert extract_host("example.com") == "example.com"
