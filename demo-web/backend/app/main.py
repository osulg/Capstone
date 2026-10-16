"""HoldFS Demo API 시작점"""

from contextlib import asynccontextmanager

from fastapi import FastAPI

from .api import runs, scenarios
from .services.runner import ScenarioRunner


@asynccontextmanager
async def lifespan(app: FastAPI):
    # 서버 전체에서 하나의 실행 관리자를 공유
    runner = ScenarioRunner(
        timeout_seconds=150,
        cleanup_seconds=5,
    )
    app.state.runner = runner

    try:
        yield
    finally:
        # 서버 종료 시 실행 중인 테스트를 정리
        await runner.close()


app = FastAPI(
    title="HoldFS Demo API",
    version="0.1.0",
    lifespan=lifespan,
)

app.include_router(
    scenarios.router,
    prefix="/api/scenarios",
)

app.include_router(
    runs.router,
    prefix="/api/runs",
)
