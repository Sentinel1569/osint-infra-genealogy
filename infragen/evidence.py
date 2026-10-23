"""Evidence provenance primitives.

Every observation this tool produces carries an :class:`Evidence` record that
answers three questions an analyst (or a reviewer of their report) will ask:

* **Where did this come from?**  ``source`` and ``url``
* **When was it collected, and has it changed since?**  ``retrieved_at`` and
  ``sha256`` of the raw bytes that were parsed
* **How much should I trust it?**  an Admiralty-style grade (source
  reliability A-F, information credibility 1-6) that maps to a numeric
  confidence in ``[0, 1]``

Conclusions are never stored as facts.  Observations are combined with
:func:`combine_confidence`, which discounts repeated reports from the same
source so ten copies of one feed do not look like ten independent witnesses.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

# NATO / Admiralty grading. Reliability describes the *source*, credibility
# describes the *specific piece of information*.
RELIABILITY = {
    "A": ("Completely reliable", 0.95),
    "B": ("Usually reliable", 0.80),
    "C": ("Fairly reliable", 0.65),
    "D": ("Not usually reliable", 0.40),
    "E": ("Unreliable", 0.20),
    "F": ("Reliability cannot be judged", 0.50),
}
CREDIBILITY = {
    1: ("Confirmed by other sources", 0.95),
    2: ("Probably true", 0.80),
    3: ("Possibly true", 0.60),
    4: ("Doubtful", 0.35),
    5: ("Improbable", 0.15),
    6: ("Truth cannot be judged", 0.50),
}


def utcnow() -> str:
    """Current UTC time as an ISO-8601 string with second precision."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def sha256_bytes(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def sha256_json(obj) -> str:
    """Stable hash of a JSON-serialisable object (sorted keys, no whitespace)."""
    return sha256_bytes(json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str))


def admiralty_confidence(reliability: str = "F", credibility: int = 6) -> float:
    """Map an Admiralty grade such as ``B2`` to a confidence in ``[0, 1]``.

    The geometric mean keeps a weak component from being hidden by a strong
    one: a completely reliable source repeating an improbable claim (A5)
    still scores low.
    """
    r = RELIABILITY.get(reliability.upper(), RELIABILITY["F"])[1]
    c = CREDIBILITY.get(int(credibility), CREDIBILITY[6])[1]
    return round((r * c) ** 0.5, 3)


def combine_confidence(items: Iterable[tuple[str, float]], same_source_decay: float = 0.3) -> float:
    """Noisy-OR combination of ``(source, confidence)`` pairs.

    Independent sources reinforce each other.  Additional reports from a
    source already counted contribute only ``same_source_decay`` of their
    weight, because they are not independent corroboration.
    """
    seen: dict[str, int] = {}
    disbelief = 1.0
    for source, conf in items:
        n = seen.get(source, 0)
        weight = 1.0 if n == 0 else same_source_decay ** n
        seen[source] = n + 1
        disbelief *= 1.0 - max(0.0, min(1.0, conf)) * weight
    return round(1.0 - disbelief, 3)


def confidence_label(conf: float) -> str:
    """Words of estimative probability (ICD 203 style)."""
    if conf >= 0.95:
        return "almost certain"
    if conf >= 0.80:
        return "very likely"
    if conf >= 0.55:
        return "likely"
    if conf >= 0.45:
        return "roughly even chance"
    if conf >= 0.20:
        return "unlikely"
    if conf >= 0.05:
        return "very unlikely"
    return "almost no chance"


@dataclass
class Evidence:
    """Provenance for one retrieval or one analytic step."""

    source: str
    url: str = ""
    retrieved_at: str = field(default_factory=utcnow)
    sha256: str = ""
    method: str = "api"  # api | dns | file | manual | derived | demo
    reliability: str = "F"
    credibility: int = 6
    note: str = ""

    @property
    def confidence(self) -> float:
        return admiralty_confidence(self.reliability, self.credibility)

    @property
    def grade(self) -> str:
        return f"{self.reliability.upper()}{self.credibility}"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["grade"] = self.grade
        d["confidence"] = self.confidence
        return d

    @classmethod
    def from_dict(cls, d: dict) -> Evidence:
        keys = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in d.items() if k in keys})
