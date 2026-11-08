"""웹 시연에서 제공하는 시나리오 목록."""

from dataclasses import dataclass


@dataclass(frozen=True)
class ScenarioStep:
    id: str
    name: str

    # 실행 결과의 steps[].name과 연결한다.
    operation_names: tuple[str, ...] = ()


@dataclass(frozen=True)
class ScenarioMode:
    id: str
    name: str
    enabled: bool = False
    disabled_reason: str | None = "실행 연결 및 검증 예정입니다."
    steps: tuple[ScenarioStep, ...] = ()


@dataclass(frozen=True)
class Scenario:
    id: str
    name: str
    category: str
    description: str
    expected_result: str
    enabled: bool
    steps: tuple[ScenarioStep, ...] = ()
    disabled_reason: str | None = None

    # 백엔드 내부에서만 사용한다.
    module: str | None = None

    modes: tuple[ScenarioMode, ...] = ()


SCENARIOS = (
    Scenario(
        id="S01",
        name="IceFire",
        category="전체 덮어쓰기",
        description=(
            "더미 문서의 전체 덮어쓰기, 확장자 변경, "
            "모의 노트 생성과 도구 표식 삭제를 시도합니다."
        ),
        expected_result=("파일 작업 결과와 HoldFS 탐지·보호 이벤트를 관찰합니다."),
        enabled=True,
        disabled_reason=None,
        module="scenarios.s01_icefire",
        steps=(
            ScenarioStep(
                id="precheck",
                name="실행 환경 확인",
                operation_names=("PRECHECK",),
            ),
            ScenarioStep(
                id="prepare",
                name="더미 문서 준비",
                operation_names=("PREPARE",),
            ),
            ScenarioStep(
                id="verify_ready",
                name="문서 공개 확인",
                operation_names=("VERIFY_READY",),
            ),
            ScenarioStep(
                id="action",
                name="공격 시도 및 보호 결과 확인",
                operation_names=("ACTION",),
            ),
        ),
    ),
    Scenario(
        id="S02",
        name="DarkRadiation",
        category="시스템 도구 기반 파일 변환",
        description=(
            "시스템 openssl로 더미 파일을 변환하고 확장자를 변경하는 작업을 시도합니다."
        ),
        expected_result=("작업 PID별 파일 변경과 HoldFS 이벤트를 관찰합니다."),
        enabled=False,
        disabled_reason="웹 실행 연결 및 Ubuntu 검증 예정입니다.",
    ),
    Scenario(
        id="S03",
        name="Huntress",
        category="읽기·허니팟·로그 삭제",
        description=(
            "더미 자격 파일 읽기, 허니팟 접근, "
            "더미 로그 삭제를 별도 작업으로 관찰합니다."
        ),
        expected_result=(
            "일반 읽기의 완료와 파일 내용 불변을 확인하고, "
            "관찰된 탐지 이벤트는 별도로 기록합니다."
        ),
        enabled=True,
        disabled_reason=None,
        module="scenarios.s03_huntress",
        modes=(
            ScenarioMode(
                id="read",
                name="일반 더미 자격 파일 읽기",
                enabled=True,
                disabled_reason=None,
            ),
            ScenarioMode(
                id="honeypot",
                name="허니팟 접근",
                enabled=True,
                disabled_reason=None,
                steps=(
                    ScenarioStep(
                        id="precheck",
                        name="실행 환경 확인",
                        operation_names=("PRECHECK",),
                    ),
                    ScenarioStep(
                        id="honeypot_ready",
                        name="미끼 준비 확인",
                        operation_names=("HONEYPOT_READY",),
                    ),
                    ScenarioStep(
                        id="honeypot_access",
                        name="허니팟 접근 결과 관찰",
                        operation_names=("HONEYPOT_ACCESS",),
                    ),
                ),
            ),
            ScenarioMode(
                id="delete",
                name="더미 로그 삭제",
                enabled=False,
                disabled_reason="최종 삭제 차단 한계로 웹 시연에서 제외했습니다.",
                steps=(
                    ScenarioStep(
                        id="precheck",
                        name="실행 환경 확인",
                        operation_names=("PRECHECK",),
                    ),
                    ScenarioStep(
                        id="prepare",
                        name="더미 로그 준비",
                        operation_names=("PREPARE",),
                    ),
                    ScenarioStep(
                        id="verify_ready",
                        name="로그 공개 확인",
                        operation_names=("VERIFY_READY",),
                    ),
                    ScenarioStep(
                        id="delete",
                        name="로그 삭제 시도",
                        operation_names=("DELETE",),
                    ),
                    ScenarioStep(
                        id="inspect",
                        name="남은 파일 확인",
                        operation_names=(
                            "INSPECT_MOUNT",
                            "INSPECT_UNDERLAY",
                        ),
                    ),
                ),
            ),
        ),
        steps=(
            ScenarioStep(
                id="precheck",
                name="실행 환경 확인",
                operation_names=("PRECHECK",),
            ),
            ScenarioStep(
                id="prepare",
                name="더미 자격 파일 준비",
                operation_names=("PREPARE",),
            ),
            ScenarioStep(
                id="verify_ready",
                name="파일 공개 확인",
                operation_names=("VERIFY_READY",),
            ),
            ScenarioStep(
                id="read",
                name="더미 파일 읽기",
                operation_names=("READ",),
            ),
            ScenarioStep(
                id="verify_content",
                name="파일 내용 불변 확인",
                operation_names=("VERIFY_MOUNT", "VERIFY_UNDERLAY"),
            ),
        ),
    ),
    Scenario(
        id="S04",
        name="Akira",
        category="부분 덮어쓰기",
        description=(
            "더미 VM 파일의 일부를 덮어쓰고 확장자 변경과 모의 노트 생성을 시도합니다."
        ),
        expected_result=("부분 변경 결과와 HoldFS 탐지·보호 이벤트를 관찰합니다."),
        enabled=False,
        disabled_reason="웹 실행 연결 및 Ubuntu 검증 예정입니다.",
    ),
)


def get_scenario(scenario_id: str) -> Scenario | None:
    """ID에 해당하는 시나리오를 반환한다."""
    return next(
        (scenario for scenario in SCENARIOS if scenario.id == scenario_id),
        None,
    )


def to_public_dict(scenario: Scenario) -> dict:
    """프런트엔드에 필요한 공개 정보만 반환한다."""
    return {
        "id": scenario.id,
        "name": scenario.name,
        "category": scenario.category,
        "description": scenario.description,
        "expected_result": scenario.expected_result,
        "enabled": scenario.enabled,
        "disabled_reason": scenario.disabled_reason,
        "steps": [
            {
                "id": step.id,
                "name": step.name,
            }
            for step in scenario.steps
        ],
        "modes": [
            {
                "id": mode.id,
                "name": mode.name,
                "enabled": mode.enabled,
                "disabled_reason": mode.disabled_reason,
                "steps": [
                    {
                        "id": step.id,
                        "name": step.name,
                    }
                    for step in mode.steps
                ],
            }
            for mode in scenario.modes
        ],
    }


def list_scenarios() -> list[dict]:
    """목록 API에서 사용할 시나리오 정보를 반환한다."""
    return [to_public_dict(scenario) for scenario in SCENARIOS]
