RECOMMENDATIONS = {
    "strict-transport-security": (
        "Enable Strict-Transport-Security (HSTS) to force browsers to use HTTPS. "
        "Example: Strict-Transport-Security: max-age=31536000; includeSubDomains"
    ),
    "content-security-policy": (
        "Add a Content-Security-Policy header to restrict which scripts, styles, "
        "images, and other resources can load on the website. "
        "Start with: Content-Security-Policy: default-src 'self'"
    ),
    "x-frame-options": (
        "Add X-Frame-Options with DENY or SAMEORIGIN to prevent clickjacking. "
        "Example: X-Frame-Options: SAMEORIGIN"
    ),
    "x-content-type-options": (
        "Set X-Content-Type-Options to nosniff to prevent MIME-type sniffing. "
        "Example: X-Content-Type-Options: nosniff"
    ),
    "referrer-policy": (
        "Set Referrer-Policy to strict-origin-when-cross-origin or no-referrer "
        "to prevent referrer information leakage. "
        "Example: Referrer-Policy: strict-origin-when-cross-origin"
    ),
    "permissions-policy": (
        "Add a Permissions-Policy header to restrict browser features like camera, "
        "microphone, and geolocation. "
        "Example: Permissions-Policy: camera=(), microphone=(), geolocation=()"
    ),
    "cross-origin-opener-policy": (
        "Add Cross-Origin-Opener-Policy to isolate browsing context. "
        "Example: Cross-Origin-Opener-Policy: same-origin"
    ),
    "cross-origin-resource-policy": (
        "Add Cross-Origin-Resource-Policy to control which origins can load your resources. "
        "Example: Cross-Origin-Resource-Policy: same-origin"
    ),
    "cross-origin-embedder-policy": (
        "Add Cross-Origin-Embedder-Policy to enforce stricter cross-origin resource embedding. "
        "Example: Cross-Origin-Embedder-Policy: require-corp"
    ),
}

RISK_MESSAGES = {
    "strict-transport-security": "Strict-Transport-Security is missing, which may allow insecure HTTP access and downgrade attacks.",
    "content-security-policy": "Content-Security-Policy is missing, which may reduce protection against cross-site scripting.",
    "x-frame-options": "X-Frame-Options is missing, which may expose the site to clickjacking attacks.",
    "x-content-type-options": "X-Content-Type-Options is missing, which may allow MIME-type sniffing attacks.",
    "referrer-policy": "Referrer-Policy is missing, which may expose referrer information to external websites.",
    "permissions-policy": "Permissions-Policy is missing, which means browser feature access is not explicitly restricted.",
    "cross-origin-opener-policy": "Cross-Origin-Opener-Policy is missing, which weakens cross-origin isolation.",
    "cross-origin-resource-policy": "Cross-Origin-Resource-Policy is missing, which may expose resources to unwanted cross-origin usage.",
    "cross-origin-embedder-policy": "Cross-Origin-Embedder-Policy is missing, which weakens advanced browser security features.",
}

DISPLAY_NAMES = {
    "strict-transport-security": "Strict-Transport-Security",
    "content-security-policy": "Content-Security-Policy",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
    "cross-origin-opener-policy": "Cross-Origin-Opener-Policy",
    "cross-origin-resource-policy": "Cross-Origin-Resource-Policy",
    "cross-origin-embedder-policy": "Cross-Origin-Embedder-Policy",
}


def generate_recommendations(headers_found: dict) -> tuple[list, list]:
    """
    Returns (recommendations: list[str], risk_summary: list[str])
    """
    recommendations = []
    risk_summary = []

    for key in RECOMMENDATIONS:
        if not headers_found.get(key, False):
            recommendations.append(RECOMMENDATIONS[key])
            risk_summary.append(RISK_MESSAGES[key])

    return recommendations, risk_summary


def get_missing_headers(headers_found: dict) -> list[str]:
    return [
        DISPLAY_NAMES[key]
        for key in DISPLAY_NAMES
        if not headers_found.get(key, False)
    ]