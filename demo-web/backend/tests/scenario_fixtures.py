"""공통 실행 제어 검사에 사용하는 정상 작업 시나리오."""

from unittest.mock import patch

from scenarios.catalog import Scenario, ScenarioStep

NORMAL_SCENARIO = Scenario(
    id="S01",
    name="테스트용 정상 파일 작업",
    category="회귀 검증",
    description="공통 실행 제어 검증용 정의입니다.",
    expected_result="정상 파일 작업과 프로세스 정리를 확인합니다.",
    enabled=True,
    module="scenarios.s01_normal",
    steps=(
        ScenarioStep(
            id="prepare_and_write",
            name="준비 및 파일 생성·쓰기",
            operation_names=("PRECHECK", "PREPARE", "CREATE", "WRITE"),
        ),
        ScenarioStep(
            id="read_and_compare",
            name="읽기 및 내용 검증",
            operation_names=("READ",),
        ),
        ScenarioStep(
            id="rename_and_verify",
            name="이름 변경 및 재검증",
            operation_names=("MKDIR", "RENAME", "READ_AFTER_RENAME"),
        ),
        ScenarioStep(
            id="delete_and_check",
            name="삭제 및 연결 상태 확인",
            operation_names=("UNLINK", "RMDIR"),
        ),
    ),
)


def get_test_scenario(scenario_id):
    """테스트에서 사용하는 정상 작업만 반환한다."""
    if scenario_id == NORMAL_SCENARIO.id:
        return NORMAL_SCENARIO
    return None


class NormalScenarioMixin:
    """각 테스트 동안 runner의 catalog 조회만 교체한다."""

    def setUp(self):
        super().setUp()

        patcher = patch(
            "app.services.runner.get_scenario",
            side_effect=get_test_scenario,
        )
        patcher.start()
        self.addCleanup(patcher.stop)
