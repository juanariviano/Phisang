"""Risk-band tests. Run from backend/: python -m pytest tests -q"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from app.risk import risk_level


@pytest.mark.parametrize("score, level", [
    (0.0, "SAFE"),
    (0.39, "SAFE"),
    (0.4, "POTENTIALLY UNSAFE"),
    (0.59, "POTENTIALLY UNSAFE"),
    (0.6, "MALICIOUS"),
    (0.79, "MALICIOUS"),
    (0.8, "High Risk"),
    (1.0, "High Risk"),
])
def test_bands(score, level):
    assert risk_level(score) == level


@pytest.mark.parametrize("score", [-0.01, 1.01, float("nan")])
def test_out_of_range_rejected(score):
    with pytest.raises(ValueError):
        risk_level(score)
