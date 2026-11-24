# """JSON API routes for the ScamRead analyzer."""

from fastapi import APIRouter

from app.extractors.regex import count_indicators, extract_indicators
from app.models.ioc import AnalyzeRequest, ExtractionResponse
# from app.analysis.rule_engine import analyze

from app.analysis.extractor import run as extract
# from app.analysis.rule_engine import analyze
from app.analysis.pipeline import analyze


router = APIRouter(prefix="/api", tags=["analysis"])


# # @router.post("/analyze", response_model=ExtractionResponse)
# # def analyze_text(payload: AnalyzeRequest) -> ExtractionResponse:
# #     """Extract IOCs from text without retaining the user's submitted content."""
# #     indicators = extract_indicators(payload.text)
# #     return ExtractionResponse(
# #         indicators=indicators,
# #         total_indicators=count_indicators(indicators),
# #     )

@router.post("/test/rule-engine")
def test_rule_engine(request: AnalyzeRequest):

    extraction = extract(request.text)

    result = analyze(
        request.text,
        extraction["indicators"],
    )

    return {
        "input": request.text,
        "extraction": extraction,
        "analysis": result,
    }

# from fastapi import APIRouter


# from app.models.ioc import AnalyzeRequest

# router = APIRouter(prefix="/api", tags=["analysis"])


@router.post("/analyze")
def analyze_text(payload: AnalyzeRequest):
    """Run the complete ScamRead analysis pipeline."""
    return analyze(payload.text)
