# Traffic analysis module
# Code Review Fix H2: Models in app/models/scoring.py, re-exported here for compatibility

from app.core.analysis.scoring import (
    ScoringEngine,
    get_scoring_engine,
    reset_scoring_engine,
)
# Re-export models from their canonical location
from app.models.scoring import ScoreBreakdown, HeuristicFactors

# Four Essentials analysis (Story 2.4)
from app.core.analysis.four_essentials import (
    FourEssentialsAnalyzer,
    FourEssentialsResult,
    EssentialAnalysis,
    AnalysisStatus,
    get_four_essentials_analyzer,
    reset_four_essentials_analyzer,
)

__all__ = [
    "ScoringEngine",
    "ScoreBreakdown",
    "HeuristicFactors",
    "get_scoring_engine",
    "reset_scoring_engine",
    # Four Essentials
    "FourEssentialsAnalyzer",
    "FourEssentialsResult",
    "EssentialAnalysis",
    "AnalysisStatus",
    "get_four_essentials_analyzer",
    "reset_four_essentials_analyzer",
]
