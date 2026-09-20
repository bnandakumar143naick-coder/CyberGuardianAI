"""
CyberGuardian AI - Phase 3 + Phase 4 + Phase 5 + Phase 7 Engines

This package contains the multi-layer threat detection and explanation
engines:
- message_engine: Extracts signals from notification/message text
- url_engine: Analyzes URL structure and brand context
- context_engine: Analyzes sender/app metadata
- threat_engine: Detects threat patterns
- evidence_engine: Collects structured evidence
- risk_engine: Evidence-based 0-100 risk scoring
- analyzer: Orchestrates the above into one pipeline (Phase 3/4)
- explainability_engine: Turns an analysis into a grounded explanation (Phase 5)
- copilot_engine: Deterministic, evidence-grounded Q&A over one analysis (Phase 7)
"""

from . import message_engine
from . import url_engine
from . import context_engine
from . import threat_engine
from . import evidence_engine
from . import risk_engine
from . import analyzer
from . import explainability_engine
from . import copilot_engine

__all__ = [
    "message_engine",
    "url_engine",
    "context_engine",
    "threat_engine",
    "evidence_engine",
    "risk_engine",
    "analyzer",
    "explainability_engine",
    "copilot_engine",
]
