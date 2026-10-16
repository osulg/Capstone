"""
scenarios/catalog.py

- 웹 시연에서 제공하는 시나리오 목록
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class ScenarioStep:
    id: str
    name: str

    # 실행 결과의 steps[].name과 연결할 항목
    operation_names: tuple[str, ...] = ()


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

    # backend 내부에서만 사용
    module: str | None = None


SCENARIOS = (
    Scenario(
        id="S01",
        name="정상 작업 및 오탐 방지",
        category="정상 · 의심",
        description=(
            "일반적인 문서 편집과 백업 작업을 구분해 정상 프로세스가 차단되지 않는지 확인합니다."
        ),
        expected_result=("업무 흐름을 방해하지 않고 정상 작업을 허용합니다."),
        enabled=True,
        module="scenarios.s01_normal",
        steps=(
            ScenarioStep(
                id="prepare_and_write",
                name="준비 및 파일 생성·쓰기",
                operation_names=(
                    "PRECHECK",
                    "PREPARE",
                    "CREATE",
                    "WRITE",
                ),
            ),
            ScenarioStep(
                id="read_and_compare",
                name="읽기 및 내용 검증",
                operation_names=("READ",),
            ),
            ScenarioStep(
                id="rename_and_verify",
                name="이름 변경 및 재검증",
                operation_names=(
                    "MKDIR",
                    "RENAME",
                    "READ_AFTER_RENAME",
                ),
            ),
            ScenarioStep(
                id="delete_and_check",
                name="삭제 및 연결 상태 확인",
                operation_names=("UNLINK", "RMDIR"),
            ),
        ),
    ),
    Scenario(
        id="S02",
        name="랜섬웨어 공격 및 원본 보호",
        category="암호화 공격",
        description=(
            "보호 폴더와 비보호 폴더에서 동일한 변경을 시도하고 "
            "원본 보호 결과를 비교합니다."
        ),
        expected_result="보호 대상 원본이 유지되는지 검증합니다.",
        enabled=False,
        disabled_reason="시나리오 구현 및 검증 예정입니다.",
    ),
    Scenario(
        id="S03",
        name="허니팟 기반 위협 탐지",
        category="미지 위협",
        description="허니팟 접근에 따른 탐지와 프로세스 상태를 확인합니다.",
        expected_result="허니팟 접근 이벤트와 탐지 결과를 확인합니다.",
        enabled=False,
        disabled_reason="시나리오 구현 및 검증 예정입니다.",
    ),
    Scenario(
        id="S04",
        name="복합 파괴형 공격",
        category="비암호화 공격",
        description="파일 변경·이름 변경·삭제에 대한 보호 결과를 확인합니다.",
        expected_result="복합 파일 훼손 시도에 대한 보호 결과를 검증합니다.",
        enabled=False,
        disabled_reason="시나리오 구현 및 검증 예정입니다.",
    ),
    Scenario(
        id="S05",
        name="정상·악성 동시 실행",
        category="다중 프로세스",
        description="정상 작업과 공격 시뮬레이션을 동시에 실행합니다.",
        expected_result="프로세스별 탐지 결과와 정상 작업 지속 여부를 검증합니다.",
        enabled=False,
        disabled_reason="시나리오 구현 및 검증 예정입니다.",
    ),
)


def get_scenario(scenario_id: str) -> Scenario | None:
    """백엔드에서 시나리오 정의를 조회"""

    return next(
        (scenario for scenario in SCENARIOS if scenario.id == scenario_id),
        None,
    )


def to_public_dict(scenario: Scenario) -> dict:
    """프런트에 필요한 정보만 반환"""

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
    }


def list_scenarios() -> list[dict]:
    """시나리오 목록 API에서 사용할 공개 데이터를 반환"""

    return [to_public_dict(scenario) for scenario in SCENARIOS]
