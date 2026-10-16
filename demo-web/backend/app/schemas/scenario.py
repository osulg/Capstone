"""
backend/schemas/scenario.py

- 시나리오 ID, 이름, 설명, 실행 가능 여부, 화면 단계, 예상 결과
- module, operation_names는 백엔드 내부 정보이므로 넣지 않음
"""

from pydantic import BaseModel, Field


class ScenarioStepResponse(BaseModel):
    id: str
    name: str


class ScenarioResponse(BaseModel):
    id: str
    name: str
    category: str
    description: str
    expected_result: str
    enabled: bool
    disabled_reason: str | None = None
    steps: list[ScenarioStepResponse] = Field(default_factory=list)
