from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from validator import validate_url
from scanner import scan_headers
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import os
from dotenv import load_dotenv
load_dotenv()

RAPIDAPI_SECRET = os.getenv("RAPIDAPI_PROXY_SECRET", "")

app = FastAPI(
    title="Website Security Headers Scanner API",
    description=(
        "A cybersecurity API that scans HTTP security headers of any website "
        "and returns a security score, grade, risk level, missing headers, "
        "and recommended fixes."
    ),
    version="1.0.0",
)

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

def rate_limit_exceeded_handler(request: Request, exc: Exception):
    return _rate_limit_exceeded_handler(request, exc)  # type: ignore[arg-type]

app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)

class ScanRequest(BaseModel):
    url: str
    follow_redirects: bool = True
    timeout: int = 10
    include_raw_headers: bool = False

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def root():
    return {
        "message": "Website Security Headers Scanner API is running.",
        "version": "1.0.0",
        "docs": "/docs",
        "endpoints": {
            "scan_headers": "POST /scan-headers",
            "check_hsts": "POST /check-hsts",
            "check_csp": "POST /check-csp",
            "check_info_disclosure": "POST /check-info-disclosure",
        },
    }


@app.get("/health")
async def health():
    return {"status": "ok"}

@app.middleware("http")
async def verify_rapidapi_proxy(request: Request, call_next):
    # Allow health check and docs without verification
    if request.url.path in ["/health", "/", "/docs", "/openapi.json"]:
        return await call_next(request)
    
    # In production, verify the secret
    if RAPIDAPI_SECRET:
        incoming_secret = request.headers.get("X-RapidAPI-Proxy-Secret", "")
        if incoming_secret != RAPIDAPI_SECRET:
            return JSONResponse(
                status_code=403,
                content={"success": False, "error": "Access denied. Use RapidAPI to access this API."}
            )
    
    return await call_next(request)

# ────────────────────────────────────────────────
# POST /scan-headers  — Full scan (MVP endpoint)
# ────────────────────────────────────────────────
@app.post("/scan-headers")
@limiter.limit("30/minute")
async def scan_headers_endpoint(request: Request, body: ScanRequest):
    is_valid, error_msg = validate_url(body.url)
    if not is_valid:
        return JSONResponse(
            status_code=400,
            content={"success": False, "error": error_msg},
        )

    result = await scan_headers(
        url=body.url,
        follow_redirects=body.follow_redirects,
        timeout=body.timeout,
        include_raw_headers=body.include_raw_headers,
    )
    return result


# ────────────────────────────────────────────────
# POST /check-hsts
# ────────────────────────────────────────────────
@app.post("/check-hsts")
@limiter.limit("30/minute")
async def check_hsts(request: Request, body: ScanRequest):
    is_valid, error_msg = validate_url(body.url)
    if not is_valid:
        return JSONResponse(status_code=400, content={"success": False, "error": error_msg})

    result = await scan_headers(
        url=body.url,
        follow_redirects=body.follow_redirects,
        timeout=body.timeout,
    )

    if not result.get("success"):
        return result

    data = result["data"]
    hsts_present = data["headers_found"].get("strict-transport-security", False)

    return {
        "success": True,
        "data": {
            "url": body.url,
            "hsts_present": hsts_present,
            "status": "pass" if hsts_present else "fail",
            "recommendation": (
                None
                if hsts_present
                else "Enable Strict-Transport-Security to force HTTPS. Example: max-age=31536000; includeSubDomains"
            ),
        },
    }


# ────────────────────────────────────────────────
# POST /check-csp
# ────────────────────────────────────────────────
@app.post("/check-csp")
@limiter.limit("30/minute")
async def check_csp(request: Request, body: ScanRequest):
    is_valid, error_msg = validate_url(body.url)
    if not is_valid:
        return JSONResponse(status_code=400, content={"success": False, "error": error_msg})

    result = await scan_headers(
        url=body.url,
        follow_redirects=body.follow_redirects,
        timeout=body.timeout,
    )

    if not result.get("success"):
        return result

    data = result["data"]
    csp_present = data["headers_found"].get("content-security-policy", False)

    return {
        "success": True,
        "data": {
            "url": body.url,
            "csp_present": csp_present,
            "status": "pass" if csp_present else "fail",
            "recommendation": (
                None
                if csp_present
                else "Add Content-Security-Policy to restrict resource loading. Example: default-src 'self'"
            ),
        },
    }


# ────────────────────────────────────────────────
# POST /check-info-disclosure
# ────────────────────────────────────────────────
@app.post("/check-info-disclosure")
@limiter.limit("30/minute")
async def check_info_disclosure(request: Request, body: ScanRequest):
    is_valid, error_msg = validate_url(body.url)
    if not is_valid:
        return JSONResponse(status_code=400, content={"success": False, "error": error_msg})

    result = await scan_headers(
        url=body.url,
        follow_redirects=body.follow_redirects,
        timeout=body.timeout,
    )

    if not result.get("success"):
        return result

    data = result["data"]
    disclosure = data["information_disclosure"]

    risks = []
    if disclosure["server_header_present"]:
        risks.append(
            f"Server header is present and reveals: '{disclosure['server_header_value']}'. "
            "Consider hiding or genericizing this header."
        )
    if disclosure["x_powered_by_present"]:
        risks.append(
            f"X-Powered-By header is present and reveals: '{disclosure['x_powered_by_value']}'. "
            "Remove this header to reduce technology fingerprinting."
        )

    return {
        "success": True,
        "data": {
            "url": body.url,
            "information_disclosure": disclosure,
            "risks": risks,
            "status": "fail" if risks else "pass",
        },
    }