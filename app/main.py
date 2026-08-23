"""FastAPI application and read-only IdentityGuard dashboard."""

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader, select_autoescape

from app.models import AnalysisResult
from app.seed import demo_dataset
from app.services.analyzer import analyze
from app.services.identity_graph import IdentityGraph
from app.services.importer import DatasetImportError, parse_dataset
from app.services.rule_engine import coverage


LOGGER = logging.getLogger("identityguard")
BASE_DIR = Path(__file__).resolve().parent
MAX_REQUEST_BYTES = 2_000_000
templates = Environment(
    loader=FileSystemLoader(BASE_DIR / "templates"),
    autoescape=select_autoescape(["html", "xml"]),
)


@asynccontextmanager
async def lifespan(application: FastAPI):
    application.state.dataset = demo_dataset()
    application.state.result = analyze(application.state.dataset)
    yield


app = FastAPI(
    title="IdentityGuard",
    description="Synthetic identity and access security analysis API",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url=None,
)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_REQUEST_BYTES:
                return JSONResponse(status_code=413, content={"error": {"code": "request_too_large", "message": "Request body exceeds the 2 MB limit."}})
        except ValueError:
            return JSONResponse(status_code=400, content={"error": {"code": "invalid_content_length", "message": "Invalid Content-Length header."}})
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
    return response


@app.exception_handler(RequestValidationError)
async def validation_error(_request: Request, _exc: RequestValidationError):
    return JSONResponse(status_code=422, content={"error": {"code": "validation_error", "message": "Request validation failed."}})


@app.exception_handler(HTTPException)
async def http_error(_request: Request, exc: HTTPException):
    messages = {
        404: "The requested resource was not found.",
        413: "Request body exceeds the supported limit.",
    }
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": {"code": f"http_{exc.status_code}", "message": messages.get(exc.status_code, "The request could not be completed.")}},
    )


@app.exception_handler(Exception)
async def unhandled_error(_request: Request, exc: Exception):
    LOGGER.exception("Unhandled application error", exc_info=exc)
    return JSONResponse(status_code=500, content={"error": {"code": "internal_error", "message": "The request could not be completed."}})


def current_result(request: Request) -> AnalysisResult:
    return request.app.state.result


async def read_bounded_body(request: Request) -> bytes:
    """Read a request incrementally without buffering more than the limit."""
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > MAX_REQUEST_BYTES:
            raise HTTPException(status_code=413, detail="Dataset exceeds the 2 MB input limit")
        body.extend(chunk)
    return bytes(body)


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def dashboard(request: Request):
    result = current_result(request)
    template = templates.get_template("dashboard.html")
    return template.render(
        summary=result.summary,
        findings=result.findings[:8],
        paths=result.attack_paths[:8],
        anomalies=result.auth_anomalies[:8],
        users=request.app.state.dataset.users,
        rules=coverage(),
    )


@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "IdentityGuard", "version": "1.0.0", "data_source": "synthetic"}


@app.get("/api/users")
async def users(request: Request):
    return request.app.state.dataset.users


@app.get("/api/users/{user_id}")
async def user_detail(user_id: str, request: Request):
    user = next((item for item in request.app.state.dataset.users if item.id == user_id), None)
    if not user:
        raise HTTPException(status_code=404, detail="Identity not found")
    graph = IdentityGraph(request.app.state.dataset)
    return {"user": user, "potential_access_paths": graph.paths_for_user(user_id), "findings": [item for item in current_result(request).findings if item.entity_id == user_id]}


@app.get("/api/findings")
async def findings(request: Request):
    return current_result(request).findings


@app.get("/api/findings/{finding_id}")
async def finding_detail(finding_id: str, request: Request):
    finding = next((item for item in current_result(request).findings if item.id == finding_id), None)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@app.post("/api/analyze")
async def run_analysis(request: Request):
    body = await read_bounded_body(request)
    if body:
        try:
            dataset = parse_dataset(body)
        except DatasetImportError:
            return JSONResponse(status_code=400, content={"error": {"code": "invalid_dataset", "message": "Dataset validation failed."}})
    else:
        dataset = demo_dataset()
    result = analyze(dataset)
    request.app.state.dataset = dataset
    request.app.state.result = result
    return result


@app.get("/api/attack-paths")
async def attack_paths(request: Request):
    return current_result(request).attack_paths


@app.get("/api/attack-paths/{user_id}")
async def user_attack_paths(user_id: str, request: Request):
    if not any(user.id == user_id for user in request.app.state.dataset.users):
        raise HTTPException(status_code=404, detail="Identity not found")
    return IdentityGraph(request.app.state.dataset).paths_for_user(user_id)


@app.get("/api/risk/summary")
async def risk_summary(request: Request):
    return current_result(request).summary


@app.get("/api/auth-events")
async def auth_events(request: Request):
    return {"events": request.app.state.dataset.authentication_events, "anomalies": current_result(request).auth_anomalies, "data_source": "synthetic"}


@app.get("/api/coverage")
async def rule_coverage():
    return {"rules": coverage(), "scope": "IdentityGuard demonstration rules; not a universal IAM standard"}
