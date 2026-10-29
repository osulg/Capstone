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


class RunProcess(BaseModel):
    """해당 실행에 등록된 작업 프로세스 정보."""

    role: str = Field(
        min_length=1,
        description="normal_worker, honeypot_worker 등 작업 역할",
    )
    pid: int = Field(gt=0)

    # PID 재사용을 구분하기 위한 Linux /proc의 프로세스 시작 값.
    # 벽시계 시각과 달리 같은 부팅 환경에서 프로세스를 식별하는 데 사용한다.
    start_time_ticks: int | None = Field(default=None, ge=0)

    registered_at: datetime


class RunResponse(BaseModel):
    """진행 상태와 최종 결과 조회"""

    run_id: str
    scenario_id: str
    status: RunStatus

    pid: int | None = None
    holdfs_pid: int | None = None

    processes: list[RunProcess] = Field(default_factory=list)

    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None

    steps: list[RunStepResponse] = Field(default_factory=list)
    result: dict[str, Any] | None = None

    detection_verification: Literal[
        "not_checked",
        "passed",
        "failed",
    ] = "not_checked"

    error: str | None = None
