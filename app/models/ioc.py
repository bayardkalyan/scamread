"""API models for deterministic indicator extraction."""

from pydantic import BaseModel, Field, field_validator


class AnalyzeRequest(BaseModel):
    """Validate pasted content before it reaches the extractor."""

    text: str = Field(
        min_length=1,
        max_length=20_000,
        description="Suspicious text, a URL, or an investigation note.",
    )

    @field_validator("text")
    @classmethod
    def reject_whitespace_only_text(cls, value: str) -> str:
        """Reject blank-looking input while preserving the original text for extraction."""
        if not value.strip():
            raise ValueError("Text must contain at least one non-space character.")
        return value


class Indicators(BaseModel):
    """Group indicators by type so clients can render them safely and clearly."""

    urls: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    email_addresses: list[str] = Field(default_factory=list)
    phone_numbers: list[str] = Field(default_factory=list)
    ipv4_addresses: list[str] = Field(default_factory=list)
    md5_hashes: list[str] = Field(default_factory=list)
    sha1_hashes: list[str] = Field(default_factory=list)
    sha256_hashes: list[str] = Field(default_factory=list)
    bitcoin_wallets: list[str] = Field(default_factory=list)
    ethereum_wallets: list[str] = Field(default_factory=list)


class ExtractionResponse(BaseModel):
    """Return only deterministic extraction data during Phase 2."""

    indicators: Indicators
    total_indicators: int
