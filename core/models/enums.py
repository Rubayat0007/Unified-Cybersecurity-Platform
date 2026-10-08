from enum import Enum


class SignalSource(str, Enum):
    AI_NIDS = "ai_nids"
    PHISHVISION = "phishvision"


class SignalStatus(str, Enum):
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    ERROR = "error"
    TIMEOUT = "timeout"
    NOT_APPLICABLE = "not_applicable"


class Severity(str, Enum):
    UNKNOWN = "unknown"
    MINIMAL = "minimal"
    LOW = "low"
    SUSPICIOUS = "suspicious"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SignalType(str, Enum):
    NETWORK_INTRUSION = "network_intrusion"
    PHISHING = "phishing"
    URL_THREAT = "url_threat"
    TEXT_THREAT = "text_threat"
    VISUAL_THREAT = "visual_threat"


class RecommendedAction(str, Enum):
    ALLOW = "allow"
    MONITOR = "monitor"
    WARN = "warn"
    INVESTIGATE = "investigate"
    BLOCK = "block"
