"""
backend/schemas/run.py

- 실행 요청, 실행 ID, 상태, PID, 단계별 진행 상태, 결과·오류
"""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

RunStatus = Literal[
    "queued",
    "running",
    "cancelling",
    "passed",
    "failed",
    "timed_out",
    "cancelled",
]

StepStatus = Literal[
    "pending",
    "running",
    "passed",
    "failed",
    "skipped",
]

HuntressMode = Literal["read", "honeypot", "delete"]


class RunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario_id: str = Field(pattern=r"^S0[1-4]$")
    mode: HuntressMode | None = None

    @model_validator(mode="after")
    def validate_mode(self):
        if self.scenario_id == "S03":
            if self.mode is None:
                raise ValueError("S03은 실행 모드를 선택해야 합니다.")
        elif self.mode is not None:
            raise ValueError("실행 모드는 S03에서만 지정할 수 있습니다.")

        return self


class RunCreatedResponse(BaseModel):
    """실행 요청을 접수한 직후 반환"""

    run_id: str
    scenario_id: str
    status: RunStatus
    mode: HuntressMode | None = None


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


class RunWorkspace(BaseModel):
    """실행별 작업 예정 경로. 실제 생성 여부를 의미하지 않는다."""

    name: str
    mount_path: str
    underlay_path: str


class RunEventCollection(BaseModel):
    """관찰 시점까지 수집한 이벤트 후보와 수집 문제.

    전체 로그의 도착이나 HoldFS 후속 처리 완료를 보장하지 않는다.
    """

    observed_at: datetime | None = None

    # JSONL 이벤트 발생 시각의 조회 상한.
    # 정책 로그는 checkpoint 이후 파일에 기록된 구간을 사용한다.
    filesystem_until_ns: int | None = None

    # 실행 전에 checkpoint를 확보한 로그 종류.
    captured_sources: list[str] = Field(default_factory=list)

    events: list[dict[str, Any]] = Field(default_factory=list)
    pid_only_events: list[dict[str, Any]] = Field(default_factory=list)

    issues: list[str] = Field(default_factory=list)
    pending_record: bool = False


class RunResponse(BaseModel):
    """진행 상태와 최종 결과 조회"""

    run_id: str
    scenario_id: str
    mode: HuntressMode | None = None
    status: RunStatus = Field(
        description=(
            "cancelling은 테스트 프로세스 종료 처리 중, "
            "cancelled는 테스트 프로세스 실행 중단 완료를 의미한다. "
            "HoldFS에 접수된 대기 작업의 폐기·처리 완료나 "
            "파일 변경의 원상복구를 의미하지 않는다."
        ),
    )

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
    workspace: RunWorkspace | None = None
    event_collection: RunEventCollection | None = None
    protection_verification: dict[str, Any] | None = None
    deletion_observation: dict[str, Any] | None = None
