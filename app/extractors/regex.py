"""Extract common indicators of compromise with readable regular expressions."""

import ipaddress
import re
from collections.abc import Iterable
from urllib.parse import urlparse

from app.models.ioc import Indicators


# Each pattern has one purpose. Validation happens separately when regex alone is not enough.
URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
EMAIL_PATTERN = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}\b", re.IGNORECASE)
DOMAIN_PATTERN = re.compile(r"\b(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,63}\b", re.IGNORECASE)
PHONE_PATTERN = re.compile(
    r"(?<!\w)(?:\+\d{1,3}[\s.-]?)?(?:\(?\d{2,4}\)?[\s.-]?){2,3}\d{3,4}(?!\w)"
)
IPV4_CANDIDATE_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# Alphanumeric boundaries prevent a hash match inside values such as 0x Ethereum wallets.
MD5_PATTERN = re.compile(r"(?<![A-Z0-9])[A-F0-9]{32}(?![A-Z0-9])", re.IGNORECASE)
SHA1_PATTERN = re.compile(r"(?<![A-Z0-9])[A-F0-9]{40}(?![A-Z0-9])", re.IGNORECASE)
SHA256_PATTERN = re.compile(r"(?<![A-Z0-9])[A-F0-9]{64}(?![A-Z0-9])", re.IGNORECASE)
BITCOIN_PATTERN = re.compile(r"\b(?:bc1[ac-hj-np-z02-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
ETHEREUM_PATTERN = re.compile(r"\b0x[A-F0-9]{40}\b", re.IGNORECASE)

# URLs often end with punctuation in normal prose; it is not part of the address.
TRAILING_URL_PUNCTUATION = ".,;:!?)]}"


def unique(values: Iterable[str]) -> list[str]:
    """Keep first-seen values, because repeat indicators add no investigation value."""
    return list(dict.fromkeys(values))


def clean_url(value: str) -> str:
    """Remove prose punctuation from a URL without changing valid path characters."""
    return value.rstrip(TRAILING_URL_PUNCTUATION)


def is_valid_ipv4(value: str) -> bool:
    """Reject regex matches such as 999.999.999.999 using Python's IP parser."""
    try:
        return isinstance(ipaddress.ip_address(value), ipaddress.IPv4Address)
    except ValueError:
        return False


def domain_from_url(url: str) -> str | None:
    """Read a hostname through URL parsing so ports and paths are not treated as domains."""
    hostname = urlparse(url).hostname
    return hostname.lower() if hostname else None


def extract_indicators(text: str) -> Indicators:
    """Extract supported indicators without assigning risk or contacting external services."""
    urls = unique(clean_url(match.group()) for match in URL_PATTERN.finditer(text))
    emails = unique(match.group().lower() for match in EMAIL_PATTERN.finditer(text))

    # Remove URLs and emails before raw-domain matching to avoid duplicate fragments.
    domain_source = URL_PATTERN.sub(" ", text)
    domain_source = EMAIL_PATTERN.sub(" ", domain_source)
    url_domains = (domain_from_url(url) for url in urls)
    raw_domains = (match.group().lower() for match in DOMAIN_PATTERN.finditer(domain_source))

    # Removing all IP-shaped values first prevents dotted numbers becoming phone fragments.
    phone_source = IPV4_CANDIDATE_PATTERN.sub(" ", text)

    return Indicators(
        urls=urls,
        domains=unique(domain for domain in (*url_domains, *raw_domains) if domain),
        email_addresses=emails,
        phone_numbers=unique(match.group() for match in PHONE_PATTERN.finditer(phone_source)),
        ipv4_addresses=unique(
            value for value in IPV4_CANDIDATE_PATTERN.findall(text) if is_valid_ipv4(value)
        ),
        md5_hashes=unique(match.group().lower() for match in MD5_PATTERN.finditer(text)),
        sha1_hashes=unique(match.group().lower() for match in SHA1_PATTERN.finditer(text)),
        sha256_hashes=unique(match.group().lower() for match in SHA256_PATTERN.finditer(text)),
        bitcoin_wallets=unique(match.group() for match in BITCOIN_PATTERN.finditer(text)),
        ethereum_wallets=unique(match.group() for match in ETHEREUM_PATTERN.finditer(text)),
    )


def count_indicators(indicators: Indicators) -> int:
    """Count all extracted values so a future dashboard can summarize the result."""
    return sum(len(values) for values in indicators.model_dump().values())
