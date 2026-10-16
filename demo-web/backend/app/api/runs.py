"""시나리오 실행 및 결과 조회 API"""

from fastapi import APIRouter, HTTPException, Request, status

from ..schemas.run import (
    RunCreatedResponse,
    RunRequest,
    RunResponse,
)
from ..services.runner import (
    RunBusyError,
    ScenarioRunner,
    ScenarioUnavailableError,
)

router = APIRouter(tags=["runs"])


def get_runner(request: Request) -> ScenarioRunner:
    """main.py에서 생성한 공용 실행 관리자를 가져온다."""
    return request.app.state.runner


@router.post(
    "",
    response_model=RunCreatedResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def create_run(body: RunRequest, request: Request):
    runner = get_runner(request)

    try:
        return runner.start(body.scenario_id)

    except ScenarioUnavailableError as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(error),
        ) from error

    except RunBusyError as error:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(error),
        ) from error


@router.get(
    "/{run_id}",
    response_model=RunResponse,
)
async def get_run(run_id: str, request: Request):
    runner = get_runner(request)

    try:
        return runner.get(run_id)

    except KeyError as error:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="존재하지 않는 실행 ID입니다.",
        ) from error
