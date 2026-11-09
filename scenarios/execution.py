"""웹 시나리오의 실행 허용 목록과 명령 구성."""

import sys
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

from scenarios.akira_config import TOTAL_TIMEOUT_SECONDS as AKIRA_TIMEOUT_SECONDS
from scenarios.huntress_config import TOTAL_TIMEOUT_SECONDS


@dataclass(frozen=True)
class ExecutionSpec:
    scenario_id: str
    module: str
    extra_args: tuple[str, ...] = ()
    timeout_seconds: float | None = None

    def workspace_name(self, run_id: str) -> str:
        return f"{self.scenario_id.lower()}_{run_id}"

    def build_command(
        self,
        *,
        mount: Path,
        underlay: Path,
        work_dir_name: str,
    ) -> list[str]:
        """웹 실행 모듈이 공통으로 받을 인자를 구성한다."""
        return [
            sys.executable,
            "-u",
            "-m",
            self.module,
            "--wait-registration-ack",
            "--mount",
            str(mount),
            "--underlay",
            str(underlay),
            "--work-dir-name",
            work_dir_name,
            *self.extra_args,
        ]


# 구현되고 실행 계약을 지원하는 모듈만 등록한다.
# 정상 작업은 catalog 전환 전 회귀 검증을 위해 유지한다.
_EXECUTIONS = MappingProxyType(
    {
        "scenarios.s01_normal": ExecutionSpec(
            scenario_id="S01",
            module="scenarios.s01_normal",
        ),
        "scenarios.s01_icefire": ExecutionSpec(
            scenario_id="S01",
            module="scenarios.s01_icefire",
            extra_args=("--run-attack",),
        ),
        "scenarios.s02_huntress": ExecutionSpec(
            scenario_id="S02",
            module="scenarios.s02_huntress",
            extra_args=(
                "--total-timeout",
                str(TOTAL_TIMEOUT_SECONDS),
            ),
            timeout_seconds=TOTAL_TIMEOUT_SECONDS,
        ),
        "scenarios.s03_akira": ExecutionSpec(
            scenario_id="S03",
            module="scenarios.s03_akira",
            extra_args=(
                "--total-timeout",
                str(AKIRA_TIMEOUT_SECONDS),
            ),
            timeout_seconds=AKIRA_TIMEOUT_SECONDS,
        ),
        "scenarios.s04_lolbin": ExecutionSpec(
            scenario_id="S04",
            module="scenarios.s04_lolbin",
            timeout_seconds=155.0,
        ),
    }
)


def get_execution(
    scenario_id: str,
    module: str | None,
) -> ExecutionSpec | None:
    """ID와 모듈 조합이 허용된 경우에만 실행 정의를 반환한다."""
    spec = _EXECUTIONS.get(module)

    if spec is None or spec.scenario_id != scenario_id:
        return None

    return spec
