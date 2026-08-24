"""
analysis.py — AEGIS-AI threat analysis via Groq.

Uses an online Groq API model.
The GROQ_API_KEY must be configured as an environment variable.
"""

from __future__ import annotations

import json
import logging
import os
import re
import textwrap
from typing import TypedDict

import requests


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public exception
# ---------------------------------------------------------------------------

class AnalysisError(Exception):
    """Raised when AI threat analysis fails."""


# ---------------------------------------------------------------------------
# Response type
# ---------------------------------------------------------------------------

class ThreatAnalysis(TypedDict):
    risk_level: str
    threat_category: str
    explanation: str
    recommendations: list[str]


VALID_RISK_LEVELS = {
    "safe",
    "low",
    "medium",
    "high",
    "critical",
}


# ---------------------------------------------------------------------------
# Groq configuration
# ---------------------------------------------------------------------------

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"

MODEL_NAME = "openai/gpt-oss-20b"


# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = textwrap.dedent("""
    You are AEGIS-AI, a cybersecurity threat detection system.

    Your job is to classify the provided text ONLY for cybersecurity threats.

    Do NOT assume something is phishing just because it is a message,
    email, business communication, or contains a request.

    Classify based on actual evidence in the text.

    REQUIRED JSON FORMAT:

    {
      "risk_level": "safe|low|medium|high|critical",
      "threat_category": "category",
      "explanation": "short explanation",
      "recommendations": [
        "recommendation 1",
        "recommendation 2",
        "recommendation 3"
      ]
    }

    DECISION RULES:

    SAFE:
    Use safe when the content is ordinary and contains no meaningful
    cybersecurity threat indicators.

    LOW:
    Use low when there is a minor security concern but no clear attack,
    malicious link, credential request, malware, or serious social
    engineering.

    MEDIUM:
    Use medium when the content contains suspicious behavior that
    requires verification, but there is not enough evidence for a clear
    attack.

    HIGH:
    Use high when there are clear indicators of phishing, credential
    theft, malicious links, impersonation, urgent requests for passwords,
    OTPs, banking information, or other sensitive information.

    CRITICAL:
    Use critical when there is evidence of an active or imminent severe
    attack such as ransomware, destructive malware, confirmed data
    exfiltration, or instructions that could immediately compromise
    systems.

    IMPORTANT:

    A normal business message is NOT automatically phishing.

    Do not invent threats that are not present in the text.

    Always return exactly 3 recommendations.

    Keep the explanation under 100 words.

    Return JSON ONLY.
""").strip()


# ---------------------------------------------------------------------------
# Build user message
# ---------------------------------------------------------------------------

def _build_user_message(text: str) -> str:
    """
    Limit the amount of text sent to the AI model.
    """

    excerpt = text[:3000]

    if len(text) > 3000:
        excerpt += "\n[... text truncated for analysis ...]"

    return (
        "Analyse this text for cybersecurity threats:\n\n"
        + excerpt
    )


# ---------------------------------------------------------------------------
# JSON extraction
# ---------------------------------------------------------------------------

def _extract_json(raw: str) -> dict:
    """
    Extract the first valid JSON object from the AI response.
    """

    if not raw:
        raise AnalysisError(
            "AI returned an empty response."
        )

    raw = raw.strip()

    # Remove markdown code fences.
    raw = re.sub(
        r"```(?:json)?",
        "",
        raw,
        flags=re.IGNORECASE,
    )

    raw = raw.replace("```", "").strip()

    # Try parsing the complete response.
    try:
        parsed = json.loads(raw)

        if isinstance(parsed, dict):
            return parsed

    except json.JSONDecodeError:
        pass

    # Find JSON inside additional text.
    match = re.search(
        r"\{[\s\S]*\}",
        raw,
    )

    if match:
        try:
            parsed = json.loads(match.group(0))

            if isinstance(parsed, dict):
                return parsed

        except json.JSONDecodeError:
            pass

    raise AnalysisError(
        "AI did not return valid JSON."
    )


# ---------------------------------------------------------------------------
# Validate and normalise result
# ---------------------------------------------------------------------------

def _validate_and_normalise(
    data: dict,
) -> ThreatAnalysis:

    # Risk level
    risk = str(
        data.get("risk_level", "")
    ).lower().strip()

    if risk not in VALID_RISK_LEVELS:
        logger.warning(
            "AI returned invalid risk level %r. "
            "Defaulting to medium.",
            risk,
        )

        risk = "medium"

    # Threat category
    category = str(
        data.get(
            "threat_category",
            "Unknown",
        )
    ).strip()

    if not category:
        category = "Unknown"

    # Explanation
    explanation = str(
        data.get(
            "explanation",
            "",
        )
    ).strip()

    if not explanation:
        explanation = (
            "Analysis completed. "
            "Review the content carefully before taking action."
        )

    # Recommendations
    recommendations = data.get(
        "recommendations",
        [],
    )

    if not isinstance(
        recommendations,
        list,
    ):
        recommendations = [
            str(recommendations)
        ]

    recommendations = [
        str(item).strip()
        for item in recommendations
        if str(item).strip()
    ]

    # Default recommendations
    default_recommendations = [
        "Treat this content with caution.",
        "Do not click links or download unexpected attachments.",
        "Report suspicious content if you are unsure.",
    ]

    while len(recommendations) < 3:
        recommendations.append(
            default_recommendations[
                len(recommendations)
            ]
        )

    # Exactly 3 recommendations
    recommendations = recommendations[:3]

    return ThreatAnalysis(
        risk_level=risk,
        threat_category=category,
        explanation=explanation,
        recommendations=recommendations,
    )


# ---------------------------------------------------------------------------
# Call Groq
# ---------------------------------------------------------------------------

def _call_ai(text: str) -> str:
    """
    Send text to the Groq AI model.
    """

    api_key = os.environ.get("GROQ_API_KEY")

    if not api_key:
        raise AnalysisError(
            "GROQ_API_KEY is not configured. "
            "Add it to the server environment variables."
        )

    payload = {
        "model": MODEL_NAME,

        "messages": [
            {
                "role": "system",
                "content": _SYSTEM_PROMPT,
            },
            {
                "role": "user",
                "content": _build_user_message(text),
            },
        ],

        "temperature": 0.1,

        "max_completion_tokens": 600,

        "response_format": {
            "type": "json_object"
        },
    }

    try:
        response = requests.post(
            GROQ_URL,

            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },

            json=payload,

            timeout=55,
        )

        response.raise_for_status()

    except requests.exceptions.Timeout as exc:

        raise AnalysisError(
            "AI analysis timed out. Please try again."
        ) from exc

    except requests.exceptions.HTTPError as exc:

        try:
            error_body = response.json()
        except Exception:
            error_body = response.text[:500]

        logger.error(
            "Groq HTTP error: %s | response=%s",
            exc,
            error_body,
        )

        raise AnalysisError(
            f"AI service returned an HTTP error: "
            f"{response.status_code}"
        ) from exc

    except requests.exceptions.RequestException as exc:

        logger.error(
            "Groq request failed: %s",
            exc,
        )

        raise AnalysisError(
            f"AI request failed: {exc}"
        ) from exc

    # Parse response
    try:

        result = response.json()

        content = (
            result["choices"][0]["message"]["content"]
        )

        if not content:
            raise ValueError("Empty AI content")

        return content

    except (
        ValueError,
        KeyError,
        TypeError,
        IndexError,
    ) as exc:

        logger.error(
            "Unexpected Groq response: %s",
            exc,
        )

        raise AnalysisError(
            "AI returned an unexpected response."
        ) from exc


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def analyse_text(
    text: str,
) -> ThreatAnalysis:

    # No readable text
    if not text or not text.strip():

        return ThreatAnalysis(
            risk_level="safe",

            threat_category="No Content",

            explanation=(
                "No readable text was found in the file. "
                "The image may be blank, contain only graphics, "
                "or the text could not be extracted by OCR."
            ),

            recommendations=[
                "Verify the file contains the content you intended to scan.",
                "Try a higher-resolution version of the image.",
                "Contact support if the problem persists.",
            ],
        )

    # Call online AI
    raw_content = _call_ai(text)

    # Extract JSON
    parsed = _extract_json(raw_content)

    # Validate result
    return _validate_and_normalise(parsed)