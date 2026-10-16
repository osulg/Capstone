"""
backend/schemas/run.py

- 실행 요청, 실행 ID, 상태, PID, 단계별 진행 상태, 결과·오류
"""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

RunStatus = Literal[
    "queued",
    "running",
    "passed",
    "failed",
    "timed_out",
]

StepStatus = Literal[
    "pending",
    "running",
    "passed",
    "failed",
    "skipped",
]


class RunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scenario_id: str = Field(pattern=r"^S0[1-5]$")


class RunCreatedResponse(BaseModel):
    """실행 요청을 접수한 직후 반환"""

    run_id: str
    scenario_id: str
    status: RunStatus


class RunStepResponse(BaseModel):
    """카탈로그의 화면 단계 ID와 연결"""

    id: str
    name: str
    status: StepStatus = "pending"
    error: str | None = None


class RunResponse(BaseModel):
    """진행 상태와 최종 결과 조회"""

    run_id: str
    scenario_id: str
    status: RunStatus

    pid: int | None = None
    holdfs_pid: int | None = None

    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None

    steps: list[RunStepResponse] = Field(default_factory=list)

    # S01이 출력한 원본 JSON 결과
    result: dict[str, Any] | None = None

    # 아직 탐지 이벤트와 연동하지 않았으므로 기본값은 미검증
    detection_verification: Literal[
        "not_checked",
        "passed",
        "failed",
    ] = "not_checked"

    error: str | None = None
