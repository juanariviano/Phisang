"""SSRF guard tests. Run from backend/: python -m pytest tests -q"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from app.url_guard import UrlRejected, check_static, classify_ip, validate

BLOCKED_SCHEMES = [
    "file:///etc/passwd",
    "gopher://127.0.0.1:6379/_INFO",
    "data:text/html,<h1>x</h1>",
    "javascript:alert(1)",
    "ftp://example.com/x",
    "ws://example.com/",
]

BLOCKED_LITERAL_IPS = [
    "http://127.0.0.1/",
    "http://127.0.0.1:8080/admin",
    "http://10.0.0.5/",
    "http://172.16.0.1/",
    "http://192.168.1.1/",
    "http://169.254.169.254/latest/meta-data/",   # AWS / GCP / Azure metadata
    "http://100.100.100.200/latest/meta-data/",   # Alibaba metadata
    "http://192.0.0.192/opc/v1/instance/",        # Oracle metadata
    "http://0.0.0.0/",
    "http://[::1]/",
    "http://[fc00::1]/",
    "http://[fe80::1]/",
    "http://[::ffff:127.0.0.1]/",                 # IPv4-mapped loopback
]

OBFUSCATED_LOOPBACK = [
    "http://2130706433/",      # decimal form of 127.0.0.1
    "http://0177.0.0.1/",      # octal
    "http://0x7f.0.0.1/",      # hex
    "http://127.1/",           # short form
    "http://localhost/",
    "http://localhost.localdomain/",
]


@pytest.mark.parametrize("url", BLOCKED_SCHEMES)
def test_scheme_rejected(url):
    with pytest.raises(UrlRejected):
        check_static(url)


@pytest.mark.parametrize("url", BLOCKED_LITERAL_IPS)
def test_literal_private_ip_rejected(url):
    with pytest.raises(UrlRejected):
        check_static(url)


@pytest.mark.parametrize("url", OBFUSCATED_LOOPBACK)
def test_obfuscated_loopback_rejected(url):
    """These need DNS/normalisation, so they must fail the full validate()."""
    with pytest.raises(UrlRejected):
        asyncio.run(validate(url))


def test_credentials_rejected():
    with pytest.raises(UrlRejected):
        check_static("http://user:pass@example.com/")


def test_disallowed_port_rejected():
    with pytest.raises(UrlRejected):
        check_static("http://example.com:22/")
    with pytest.raises(UrlRejected):
        check_static("http://example.com:6379/")


def test_overlong_url_rejected():
    with pytest.raises(UrlRejected):
        check_static("https://example.com/" + "a" * 3000)


def test_no_host_rejected():
    with pytest.raises(UrlRejected):
        check_static("http:///nohost")


def test_public_url_accepted():
    host, port = check_static("https://example.com/login?a=1")
    assert host == "example.com"
    assert port == 443


def test_public_ip_accepted():
    assert classify_ip("8.8.8.8") == ""
    assert classify_ip("1.1.1.1") == ""


def test_classify_ip_reasons():
    assert "loopback" in classify_ip("127.0.0.1")
    assert "non-routable" in classify_ip("100.100.100.200")
    assert classify_ip("not-an-ip") == "unparseable IP address"
