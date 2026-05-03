HEADER_SCORES = {
    "strict-transport-security": 20,
    "content-security-policy": 25,
    "x-frame-options": 10,
    "x-content-type-options": 10,
    "referrer-policy": 10,
    "permissions-policy": 10,
    "cross-origin-opener-policy": 5,
    "cross-origin-resource-policy": 5,
    "cross-origin-embedder-policy": 5,
}

GRADE_TABLE = [
    (90, "A", "Low"),
    (75, "B", "Low to Medium"),
    (60, "C", "Medium"),
    (40, "D", "High"),
    (0,  "F", "Critical"),
]


def calculate_score(headers_found: dict) -> int:
    score = 0
    for header_key, points in HEADER_SCORES.items():
        if headers_found.get(header_key, False):
            score += points
    return score


def calculate_grade(score: int) -> tuple[str, str]:
    for threshold, grade, risk in GRADE_TABLE:
        if score >= threshold:
            return grade, risk
    return "F", "Critical"