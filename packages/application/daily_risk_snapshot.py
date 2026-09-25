"""Application boundary for the sole pure runtime evidence validator.

The future account transaction authenticates retained producer references before
calling this function. This wrapper performs no reads, effects or authentication.
"""

from packages.domain.daily_runtime_risk import (
    build_daily_runtime_evidence as build_daily_runtime_evidence,
)
from packages.domain.daily_runtime_risk import (
    runtime_source_value_sha256 as runtime_source_value_sha256,
)
