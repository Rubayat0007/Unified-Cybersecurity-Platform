from collections.abc import Mapping
from typing import Any

from core.evidence.model import Evidence
from core.models.enums import (
    Severity,
    SignalSource,
    SignalStatus,
    SignalType,
)
from core.models.signal import SecuritySignal


_SEVERITY_RANK = {
    Severity.MINIMAL: 0,
    Severity.LOW: 1,
    Severity.SUSPICIOUS: 2,
    Severity.MEDIUM: 3,
    Severity.HIGH: 4,
    Severity.CRITICAL: 5,
}


def _require_mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{name} must be a mapping")
    return value


def _finite_number(value: Any, name: str) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be numeric") from exc

    if result != result or result in (float("inf"), float("-inf")):
        raise ValueError(f"{name} must be finite")

    return result


def _score_0_to_100(value: Any, name: str) -> float:
    result = _finite_number(value, name)

    if not 0.0 <= result <= 100.0:
        raise ValueError(f"{name} must be between 0 and 100")

    return result


def _probability_0_to_1(value: Any, name: str) -> float:
    result = _finite_number(value, name)

    if not 0.0 <= result <= 1.0:
        raise ValueError(f"{name} must be between 0 and 1")

    return result


def _status_from_result(
    result: Mapping[str, Any],
    *,
    default_available: bool = True,
) -> SignalStatus:
    if result.get("error"):
        return SignalStatus.ERROR

    if default_available:
        return SignalStatus.AVAILABLE

    return SignalStatus.UNAVAILABLE


def _max_finding_severity(
    findings: Any,
    source_name: str,
) -> Severity | None:
    if not isinstance(findings, list):
        return None

    best: Severity | None = None

    for finding in findings:
        if not isinstance(finding, Mapping):
            continue

        if finding.get("source") != source_name:
            continue

        raw_severity = finding.get("severity")
        if not isinstance(raw_severity, str):
            continue

        try:
            severity = Severity(raw_severity.lower())
        except ValueError:
            continue

        if best is None or _SEVERITY_RANK[severity] > _SEVERITY_RANK[best]:
            best = severity

    return best


def _fallback_suspicion_severity(
    value: Any,
) -> Severity | None:
    """Map the analyzer's categorical suspicion flag conservatively."""
    if not isinstance(value, bool):
        return None

    return Severity.MEDIUM if value else Severity.LOW


def _fallback_prediction_severity(
    value: Any,
) -> Severity | None:
    """Map the CNN's existing prediction when no CNN finding exists."""
    if not isinstance(value, str):
        return None

    prediction = value.strip().lower()

    if prediction == "phishing":
        return Severity.MEDIUM

    if prediction == "legitimate":
        return Severity.LOW

    return None


def _build_evidence(
    findings: Any,
    source_name: str,
) -> tuple[Evidence, ...]:
    if not isinstance(findings, list):
        return ()

    evidence_items: list[Evidence] = []

    for finding in findings:
        if not isinstance(finding, Mapping):
            continue

        if finding.get("source") != source_name:
            continue

        category = finding.get("category")
        description = finding.get("evidence")

        if not isinstance(category, str):
            continue

        if not isinstance(description, str):
            description = str(description)

        evidence_items.append(
            Evidence(
                source=SignalSource.PHISHVISION,
                category=category,
                description=description,
                evidence_type=source_name.lower(),
                value=finding.get("evidence"),
                metadata={
                    "component_severity": finding.get("severity"),
                },
            )
        )

    return tuple(evidence_items)


def adapt_result(
    result: Mapping[str, Any],
) -> tuple[SecuritySignal, ...]:
    """
    Convert a production PhishVision analyzer result into normalized
    component-level SecuritySignal objects.

    The existing PhishVision composite risk is preserved as metadata.
    It is intentionally not emitted as another signal so that text,
    URL, and CNN evidence are not double-counted by the unified engine.
    """
    result = _require_mapping(result, "result")

    text_result = _require_mapping(
        result.get("text_analysis"),
        "text_analysis",
    )

    cnn_result = _require_mapping(
        result.get("cnn_analysis"),
        "cnn_analysis",
    )

    url_result_raw = result.get("url_analysis")

    if url_result_raw is not None:
        url_result = _require_mapping(
            url_result_raw,
            "url_analysis",
        )
    else:
        url_result = None

    risk_result_raw = result.get("risk")
    risk_result = (
        _require_mapping(risk_result_raw, "risk")
        if risk_result_raw is not None
        else {}
    )

    assessment_raw = result.get("security_assessment")
    assessment = (
        _require_mapping(assessment_raw, "security_assessment")
        if assessment_raw is not None
        else {}
    )

    findings = assessment.get("evidence", [])

    common_metadata = {
        "overall_score": risk_result.get("overall_score"),
        "overall_risk_level": risk_result.get("risk_level"),
    }

    # ---------------------------------------------------------
    # Text / OCR
    # ---------------------------------------------------------
    text_status = _status_from_result(text_result)

    if text_status is SignalStatus.AVAILABLE:
        text_score = _score_0_to_100(
            text_result.get("score"),
            "text_analysis.score",
        )
    else:
        text_score = None


    text_severity = _max_finding_severity(findings, "OCR")

    if (
        text_severity is None
        and text_status is SignalStatus.AVAILABLE
    ):
        text_severity = _fallback_suspicion_severity(
            text_result.get("is_suspicious")
        )


    text_signal = SecuritySignal(
        source=SignalSource.PHISHVISION,
        signal_type=SignalType.TEXT_THREAT,
        status=text_status,
        raw_score=text_score,
        raw_score_semantics="heuristic_text_score",
        normalized_score=text_score,
        confidence=None,
        severity=text_severity,
        evidence=_build_evidence(findings, "OCR"),
        metadata={
            **common_metadata,
            "matches": tuple(text_result.get("matches", [])),
        },
    )

    signals = [text_signal]

    # ---------------------------------------------------------
    # URL
    # ---------------------------------------------------------
    if url_result is None:
        url_signal = SecuritySignal(
            source=SignalSource.PHISHVISION,
            signal_type=SignalType.URL_THREAT,
            status=SignalStatus.NOT_APPLICABLE,
            raw_score=None,
            raw_score_semantics="heuristic_url_score",
            normalized_score=None,
            confidence=None,
            severity=None,
            evidence=(),
            metadata={
                **common_metadata,
                "reason": "No URL was supplied to PhishVision.",
            },
        )
    else:
        url_status = _status_from_result(url_result)

        if url_status is SignalStatus.AVAILABLE:
            url_score = _score_0_to_100(
                url_result.get("score"),
                "url_analysis.score",
            )
        else:
            url_score = None

        url_severity = _max_finding_severity(findings, "URL")

        if (
            url_severity is None
            and url_status is SignalStatus.AVAILABLE
        ):
            url_severity = _fallback_suspicion_severity(
                url_result.get("is_suspicious")
            )

        url_signal = SecuritySignal(
            source=SignalSource.PHISHVISION,
            signal_type=SignalType.URL_THREAT,
            status=url_status,
            raw_score=url_score,
            raw_score_semantics="heuristic_url_score",
            normalized_score=url_score,
            confidence=None,
            severity=url_severity,
            evidence=_build_evidence(findings, "URL"),
            metadata={
                **common_metadata,
                "hostname": url_result.get("hostname"),
                "indicators": tuple(url_result.get("indicators", [])),
                "matched_keywords": tuple(
                    url_result.get("matched_keywords", [])
                ),
            },
        )

    signals.append(url_signal)

    # ---------------------------------------------------------
    # CNN / visual phishing
    # ---------------------------------------------------------
    model_loaded = bool(cnn_result.get("model_loaded"))
    cnn_error = cnn_result.get("error")

    if not model_loaded:
        cnn_status = SignalStatus.UNAVAILABLE
    elif cnn_error or cnn_result.get("phishing_probability") is None:
        cnn_status = SignalStatus.ERROR
    else:
        cnn_status = SignalStatus.AVAILABLE

    if cnn_status is SignalStatus.AVAILABLE:
        phishing_probability = _probability_0_to_1(
            cnn_result.get("phishing_probability"),
            "cnn_analysis.phishing_probability",
        )
        normalized_cnn_score = phishing_probability * 100.0
    else:
        phishing_probability = None
        normalized_cnn_score = None

    cnn_severity = _max_finding_severity(findings, "CNN")

    if (
        cnn_severity is None
        and cnn_status is SignalStatus.AVAILABLE
    ):
        cnn_severity = _fallback_prediction_severity(
            cnn_result.get("prediction")
        )

    cnn_signal = SecuritySignal(
        source=SignalSource.PHISHVISION,
        signal_type=SignalType.VISUAL_THREAT,
        status=cnn_status,
        raw_score=phishing_probability,
        raw_score_semantics="phishing_probability",
        normalized_score=normalized_cnn_score,
        confidence=None,
        severity=cnn_severity,
        evidence=_build_evidence(findings, "CNN"),
        metadata={
            **common_metadata,
            "prediction": cnn_result.get("prediction"),
            "legitimate_probability": cnn_result.get(
                "legitimate_probability"
            ),
            "threshold": cnn_result.get("threshold"),
            "model_loaded": model_loaded,
        },
    )

    signals.append(cnn_signal)

    return tuple(signals)