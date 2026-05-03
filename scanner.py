import time
import httpx
from scorer import calculate_score, calculate_grade
from recommender import generate_recommendations, get_missing_headers

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
    "cross-origin-embedder-policy",
]

WEAK_HEADER_RULES = {
    "x-content-type-options": lambda v: v.strip().lower() != "nosniff",
    "x-frame-options": lambda v: v.strip().upper() not in ("DENY", "SAMEORIGIN"),
}


async def scan_headers(
    url: str,
    follow_redirects: bool = True,
    timeout: int = 10,
    include_raw_headers: bool = False,
) -> dict:
    start_time = time.time()

    try:
        async with httpx.AsyncClient(
            follow_redirects=follow_redirects,
            timeout=timeout,
            limits=httpx.Limits(max_connections=5),
        ) as client:
            response = await client.get(
                url,
                headers={
                    "User-Agent": "SecurityHeadersScanner/1.0"
                },
            )
    except httpx.TimeoutException:
        return {"success": False, "error": "Website request timed out"}
    except httpx.ConnectError:
        return {"success": False, "error": "Unable to reach the website"}
    except httpx.TooManyRedirects:
        return {"success": False, "error": "Too many redirects"}
    except Exception as e:
        return {"success": False, "error": f"Request failed: {str(e)}"}

    elapsed_ms = round((time.time() - start_time) * 1000)
    response_headers = {k.lower(): v for k, v in response.headers.items()}

    # Check which security headers are present
    headers_found = {header: header in response_headers for header in SECURITY_HEADERS}

    # Detect weak headers
    weak_headers = []
    for header, is_weak_fn in WEAK_HEADER_RULES.items():
        if header in response_headers:
            value = response_headers[header]
            if is_weak_fn(value):
                weak_headers.append(
                    f"{header}: '{value}' — value may be weak or misconfigured"
                )

    # Information disclosure
    server_header = response_headers.get("server", None)
    x_powered_by = response_headers.get("x-powered-by", None)
    information_disclosure = {
        "server_header_present": server_header is not None,
        "server_header_value": server_header if server_header else None,
        "x_powered_by_present": x_powered_by is not None,
        "x_powered_by_value": x_powered_by if x_powered_by else None,
    }

    # Score and grade
    score = calculate_score(headers_found)
    grade, risk_level = calculate_grade(score)

    # Recommendations and risk summary
    recommendations, risk_summary = generate_recommendations(headers_found)
    missing_headers = get_missing_headers(headers_found)

    result = {
        "url": url,
        "status_code": response.status_code,
        "security_score": score,
        "grade": grade,
        "risk_level": risk_level,
        "headers_found": headers_found,
        "missing_headers": missing_headers,
        "weak_headers": weak_headers,
        "information_disclosure": information_disclosure,
        "risk_summary": risk_summary,
        "recommendations": recommendations,
        "scan_time_ms": elapsed_ms,
    }

    if include_raw_headers:
        result["raw_headers"] = dict(response.headers)

    return {"success": True, "data": result}