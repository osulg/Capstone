"""시나리오 목록 조회 API"""

from fastapi import APIRouter

from scenarios.catalog import list_scenarios

from ..schemas.scenario import ScenarioResponse

router = APIRouter(tags=["scenarios"])


@router.get("", response_model=list[ScenarioResponse])
async def get_scenarios():
    return list_scenarios()
