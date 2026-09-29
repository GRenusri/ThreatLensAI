MAX_INPUT_LENGTH = 2000


def validate_input(user_input):
    # Check 1: Reject empty input
    if not user_input:
        return {
            "allowed": False,
            "reason": "Input cannot be empty"
        }

    # Check 2: Reject extremely long input
    if len(user_input) > MAX_INPUT_LENGTH:
        return {
            "allowed": False,
            "reason": "Input exceeds maximum length"
        }

    # Normalize input before checking it
    normalized_input = user_input.lower()

    # Basic suspicious prompt-injection patterns
    suspicious_patterns = [
        "ignore previous instructions",
        "ignore all previous instructions",
        "reveal system prompt",
        "show system prompt",
        "bypass security",
        "disable security",
        "forget your instructions"
    ]

    # Check every suspicious pattern
    for pattern in suspicious_patterns:
        if pattern in normalized_input:
            return {
                "allowed": False,
                "reason": "Possible prompt injection detected",
                "matched_pattern": pattern
            }

    # Input passed our checks
    return {
        "allowed": True,
        "reason": "Input passed validation"
    }