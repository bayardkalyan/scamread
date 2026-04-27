import logging
from openai import APIConnectionError, APIStatusError, APITimeoutError, OpenAI

from app.config import Settings
from app.errors import fallback_analysis
from app.schemas import ScamAnalysis

logger = logging.getLogger(__name__)


SYSTEM_PROMPT = """
You are ScamRead, a careful scam-risk analysis engine.

Analyze the user's pasted message or link for signs of fraud, phishing,
malware, impersonation, fake prizes, romance scams, investment scams,
payment scams, account takeover attempts, extortion, urgency manipulation,
credential theft, suspicious links, or social engineering.

Return only the structured fields requested by the schema.
Be concise, practical, and avoid claiming certainty when evidence is limited.
If the input is too vague to assess, choose a lower score and explain what
additional evidence would be needed.
""".strip()


class AnalyzerError(RuntimeError):
    def __init__(self, message: str, status_code: int = 503):
        super().__init__(message)
        self.message = message
        self.status_code = status_code

    def to_analysis(self) -> ScamAnalysis:
        return fallback_analysis(explanation=self.message)


class ScamAnalyzer:
    def __init__(self, settings: Settings):
        if not settings.openai_api_key:
            raise AnalyzerError(
                "ScamRead is not configured with an OpenAI API key.",
                status_code=503,
            )

        self.client = OpenAI(
            api_key=settings.openai_api_key,
            timeout=settings.request_timeout_seconds,
        )
        self.model = settings.openai_model

    def analyze(self, text: str) -> ScamAnalysis:
        try:
            response = self.client.responses.parse(
                model=self.model,
                input=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": text},
                ],
                text_format=ScamAnalysis,
            )
        except (APIConnectionError, APITimeoutError) as exc:
            logger.warning("OpenAI connection failure: %s", exc)
            raise AnalyzerError("Could not reach the analysis service. Please try again.") from exc
        except APIStatusError as exc:
            logger.warning("OpenAI API status error: %s", exc)
            raise openai_status_error(exc) from exc
        except Exception as exc:
            logger.exception("Unexpected analysis failure")
            raise AnalyzerError("Analysis failed unexpectedly. Please try again.") from exc

        if response.output_parsed is None:
            raise AnalyzerError("The analysis service returned an empty result.")

        return normalize_analysis(response.output_parsed)


def normalize_analysis(analysis: ScamAnalysis) -> ScamAnalysis:
    analysis.risk_score = max(0, min(100, analysis.risk_score))
    analysis.scam_type = analysis.scam_type.strip() or "unknown"
    analysis.red_flags = [flag.strip() for flag in analysis.red_flags if flag.strip()]
    analysis.explanation = analysis.explanation.strip()
    analysis.recommended_action = analysis.recommended_action.strip()

    if not analysis.red_flags:
        analysis.red_flags = ["No specific red flags identified."]
    if not analysis.explanation:
        analysis.explanation = "The analysis completed but did not include a detailed explanation."
    if not analysis.recommended_action:
        analysis.recommended_action = "Use caution and avoid clicking links or sharing sensitive information."

    return analysis


def openai_status_error(exc: APIStatusError) -> AnalyzerError:
    code = getattr(exc, "code", None)
    status_code = getattr(exc, "status_code", 503)

    if status_code == 401:
        return AnalyzerError(
            "OpenAI rejected the API key. Check that OPENAI_API_KEY in .env is valid for this project.",
            status_code=503,
        )

    if status_code == 403:
        return AnalyzerError(
            "OpenAI rejected the request because this key does not have access to the configured model.",
            status_code=503,
        )

    if status_code == 404:
        return AnalyzerError(
            "The configured OpenAI model was not found. Check OPENAI_MODEL in .env.",
            status_code=503,
        )

    if status_code == 429 and code == "insufficient_quota":
        return AnalyzerError(
            "OpenAI returned insufficient_quota. The API key is loaded, but the account or project needs available credits or billing enabled.",
            status_code=503,
        )

    if status_code == 429:
        return AnalyzerError(
            "OpenAI rate-limited the analysis request. Wait a moment and try again.",
            status_code=503,
        )

    return AnalyzerError(
        "The analysis service returned an error. Please try again later.",
        status_code=503,
    )
