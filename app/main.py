import logging
from pathlib import Path


from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import ValidationError

from app.errors import fallback_analysis
from app.logic import analyze_scam
from app.schemas import AnalyzeRequest, ScamAnalysis


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(
    title="ScamRead",
    description="Paste a message or link and get scam risk analysis.",
    version="0.1.0",
)

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


def analysis_response(analysis: ScamAnalysis, status_code: int = 200) -> JSONResponse:
    return JSONResponse(status_code=status_code, content=analysis.model_dump())


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    if request.url.path == "/analyze":
        return analysis_response(
            fallback_analysis(
                explanation="The request must include a non-empty 'text' string up to 8000 characters.",
                recommended_action="Paste the suspicious message or link into the text box and try again.",
                risk_level="low",
                risk_score=0,
            ),
            status_code=400,
        )

    return JSONResponse(status_code=422, content={"detail": exc.errors()})


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/analyze", response_model=ScamAnalysis)
def analyze(payload: AnalyzeRequest) -> JSONResponse:
    text = payload.text.strip()
    if not text:
        return analysis_response(
            fallback_analysis(
                explanation="The request must include a non-empty message or link.",
                recommended_action="Paste the suspicious content and run the analysis again.",
                risk_level="low",
                risk_score=0,
            ),
            status_code=400,
        )

    try:
        result = analyze_scam(text)
        analysis = ScamAnalysis.model_validate(result)
        return analysis_response(analysis)
    except ValidationError as exc:
        logger.exception("Rule-based analyzer returned invalid output")
        return analysis_response(
            fallback_analysis(
                explanation="The rule-based analyzer returned an invalid result shape.",
                recommended_action="Try again later.",
            ),
            status_code=500,
        )
    except Exception as exc:
        logger.exception("Rule-based analyzer failed")
        return analysis_response(
            fallback_analysis(
                explanation=f"Analysis failed unexpectedly: {exc}",
                recommended_action="Try again later.",
            ),
            status_code=500,
        )
