"""
HoldFS EDR Dashboard 서버

- 에이전트(agent.py)가 HoldFS 정책 수행 결과를 JSON으로 POST /api/events 에 전송
- 보안팀 대시보드(/)가 2초마다 이벤트를 폴링해 실시간 표시
- AI 보안 분석관(POST /api/chat)이 이벤트 로그 + 지식 베이스를 RAG로 검색해 LLM에 질의

실행:
    export OPENAI_API_KEY=sk-...        # 없으면 규칙 기반 로컬 분석으로 동작
    python dashboard/server.py --port 5000
"""

import argparse
import os
import threading
import time

from flask import Flask, jsonify, request, send_from_directory

try:
    from dashboard.rag import (
        STAGE2_DYN_ONLY_HIGH_THRESHOLD,
        STAGE2_HIGH_THRESHOLD,
        STAGE2_MEDIUM_THRESHOLD,
        build_context,
        local_analysis,
    )
    from dashboard import files as file_scan
    from dashboard import system as sys_status
except ImportError:  # python dashboard/server.py 로 직접 실행한 경우
    from rag import (
        STAGE2_DYN_ONLY_HIGH_THRESHOLD,
        STAGE2_HIGH_THRESHOLD,
        STAGE2_MEDIUM_THRESHOLD,
        build_context,
        local_analysis,
    )
    import files as file_scan
    import system as sys_status

# MEDIUM 관찰 시간: 보류된 쓰기가 원본에 반영되기까지 (파일 현황 › 보류 중인 쓰기의 남은 시간)
try:
    from guardfs.common.config import STAGE2_MEDIUM_TIMEOUT_SEC
except ImportError:
    STAGE2_MEDIUM_TIMEOUT_SEC = 10.0

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None

# React 화면 빌드 결과 (dashboard/web 에서 npm run build)
WEB_DIST = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web", "dist")

app = Flask(__name__, static_folder=None)

MAX_EVENTS = 5000
events = []  # in-memory log store
_events_lock = threading.Lock()
_next_id = 1
# 서버 재시작/로그 비우기 시 바뀌는 값. 대시보드는 이 값이 바뀌면 테이블을 다시 받는다.
_generation = int(time.time() * 1000)

OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")

# AI 분석관 남용 방지 (외부 LLM 호출 = API 요금). 환경변수로 바꿀 수 있다.
CHAT_MAX_QUESTION_CHARS = int(os.environ.get("DASH_CHAT_MAX_CHARS", "2000"))   # 질문 최대 길이
CHAT_MAX_HISTORY_CHARS = 4000        # 이전 대화 한 턴의 최대 길이 (최근 8턴만 보냄)
CHAT_MAX_TOKENS = int(os.environ.get("DASH_CHAT_MAX_TOKENS", "2048"))           # 답변 최대 길이(토큰)
# Gemini 2.5 같은 '생각(thinking)' 모델은 생각 토큰도 max_tokens 에 포함돼, 그대로 두면 답이 첫 문장에서
# 잘린다. OpenAI 호환 API 의 reasoning_effort 로 생각 단계를 끈다(Gemini 2.5 Flash: "none").
# 다른 제공자에는 보내지 않는다. 값은 DASH_CHAT_REASONING 로 바꿀 수 있다("" = 보내지 않음).
_IS_GEMINI = "generativelanguage.googleapis.com" in os.environ.get("OPENAI_BASE_URL", "")
CHAT_REASONING = os.environ.get("DASH_CHAT_REASONING", "none" if _IS_GEMINI else "")
CHAT_RATE_PER_MIN = int(os.environ.get("DASH_CHAT_RATE_PER_MIN", "10"))         # LLM 호출 분당 최대 횟수(서버 전체)
_chat_calls: list[float] = []
_chat_lock = threading.Lock()


def _chat_rate_ok() -> bool:
    """최근 60초 동안의 LLM 호출 수가 한도 미만이면 이번 호출을 기록하고 True."""
    now = time.time()
    with _chat_lock:
        while _chat_calls and now - _chat_calls[0] > 60:
            _chat_calls.pop(0)
        if len(_chat_calls) >= CHAT_RATE_PER_MIN:
            return False
        _chat_calls.append(now)
        return True
_llm_client = None
if OpenAI is not None and os.environ.get("OPENAI_API_KEY"):
    _llm_client = OpenAI()

SYSTEM_PROMPT = f"""당신은 엔드포인트 보안 분석 전문가입니다. HoldFS EDR 시스템의 보안 이벤트 로그를 분석하여 보안팀에게 인사이트를 제공합니다.

HoldFS 시스템 개요:
- FUSE 기반 실시간 파일 보호 정책 엔진
- Stage1: 엔트로피 탐지 / 삭제 빈도 / 허니팟 접근 → score ≥ 1이면 ML 평가
- Stage2: 동적 RF + 정적 RF 앙상블 (가중치 0.5/0.5)
- MEDIUM (score {STAGE2_MEDIUM_THRESHOLD}~{STAGE2_HIGH_THRESHOLD}): write 버퍼링 + 1초 주기 재평가
- HIGH (score ≥ {STAGE2_HIGH_THRESHOLD} 또는 동적 점수 단독 ≥ {STAGE2_DYN_ONLY_HIGH_THRESHOLD}): write/rename/unlink/truncate 차단 + SIGSTOP

MITRE ATT&CK 주요 매핑:
- T1486 Data Encrypted for Impact: 고엔트로피 write + 확장자 변경
- T1485 Data Destruction: 원본 파일 삭제 패턴
- T1083 File and Directory Discovery: 허니팟 접근
- T1036 Masquerading: 확장자 위장

보안팀의 질문에 대해 현재 이벤트 로그를 기반으로 다음을 제공하세요:
- 공격 진행 경위 분석
- MITRE ATT&CK 기법 매핑
- 랜섬웨어 패밀리 유사도
- 즉각 대응 방안
- 추가 모니터링 권고사항

한국어로 답변하되, 기술 용어는 영어 병기를 사용하세요. 답변은 명확하고 간결하게 작성하세요."""

RAG_INSTRUCTION = """아래는 질문과 관련해 검색된 HoldFS EDR 이벤트 로그와 참고 지식입니다.
반드시 이 근거에 있는 시각, PID, 파일 경로, 점수, 격상 사유를 인용해서 답하세요.
근거에 없는 사실은 추측이라고 명시하세요. 마크다운(### 소제목, **굵게**, 번호 목록)으로 작성하세요.

{context}"""

# 에이전트가 보내는 필드 → 기본값
EVENT_FIELDS = {
    "time": "",
    "level": "LOW",
    "pid": 0,
    "process": "-",
    "target": "",
    "action": "",
    "result": "",
    "reason": "",
    "source": "agent",
    "host": "",
}


def _normalize(raw: dict) -> dict:
    ev = {k: raw.get(k, v) for k, v in EVENT_FIELDS.items()}
    try:
        ev["pid"] = int(ev["pid"])
    except (TypeError, ValueError):
        ev["pid"] = 0
    ev["level"] = str(ev["level"]).upper()
    ev["action"] = str(ev["action"])
    ev["result"] = str(ev["result"]).upper()
    ev["process"] = ev["process"] or "-"
    ts = raw.get("ts")
    if ts is None and ev["time"]:
        # HoldFS·agent 시각은 "YYYY-MM-DD HH:MM:SS" 또는 밀리초가 붙은 "…SS.mmm"
        base, _, frac = str(ev["time"]).partition(".")
        try:
            ts = time.mktime(time.strptime(base, "%Y-%m-%d %H:%M:%S"))
            if frac.isdigit():
                ts += int(frac) / 10 ** len(frac)
        except ValueError:
            ts = None
    ev["ts"] = float(ts) if ts is not None else time.time()
    if not ev["time"]:
        ev["time"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ev["ts"]))
    return ev


def _stats(evs: list) -> dict:
    return {
        "total": len(evs),
        "high": sum(1 for e in evs if e["level"] == "HIGH"),
        "medium": sum(1 for e in evs if e["level"] == "MEDIUM"),
        "blocked": sum(1 for e in evs if e["result"] == "BLOCKED"),
        "high_pids": sorted({e["pid"] for e in evs if e["level"] == "HIGH"}),
        "medium_pids": sorted({e["pid"] for e in evs if e["level"] == "MEDIUM"}),
    }


def _snapshot() -> list:
    with _events_lock:
        return list(events)


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #

@app.route("/")
def index():
    if not os.path.isfile(os.path.join(WEB_DIST, "index.html")):
        return ("대시보드 화면 빌드가 없습니다. dashboard/web 에서 npm ci && npm run build 를 실행하세요.",
                503, {"Content-Type": "text/plain; charset=utf-8"})
    return send_from_directory(WEB_DIST, "index.html")


@app.route("/assets/<path:name>")
def web_assets(name):
    return send_from_directory(os.path.join(WEB_DIST, "assets"), name)


@app.route("/api/events", methods=["POST"])
def receive_events():
    """에이전트 수신 엔드포인트. 단일 객체 또는 리스트를 받는다."""
    global _next_id
    payload = request.get_json(silent=True)
    if payload is None:
        return jsonify({"error": "JSON body required"}), 400
    items = payload if isinstance(payload, list) else [payload]

    added = 0
    with _events_lock:
        for raw in items:
            if not isinstance(raw, dict):
                continue
            ev = _normalize(raw)
            ev["id"] = _next_id
            _next_id += 1
            events.append(ev)
            added += 1
        if len(events) > MAX_EVENTS:
            del events[: len(events) - MAX_EVENTS]
    return jsonify({"ok": True, "added": added})


@app.route("/api/events", methods=["GET"])
def list_events():
    """since_id 이후 이벤트만 돌려준다 (대시보드 증분 폴링용)."""
    since_id = request.args.get("since_id", default=0, type=int)
    generation = request.args.get("gen", default=0, type=int)
    evs = _snapshot()
    reset = generation != _generation
    new = evs if reset else [e for e in evs if e["id"] > since_id]
    return jsonify({"events": new, "stats": _stats(evs), "reset": reset,
                    "gen": _generation, "last_id": evs[-1]["id"] if evs else 0})


@app.route("/api/events", methods=["DELETE"])
def clear_events():
    global _generation
    with _events_lock:
        events.clear()
        _generation += 1
    return jsonify({"ok": True})


@app.route("/api/files")
def list_files():
    """파일 상태 탭: 보호/비보호 폴더 스캔 결과 (읽기 전용)."""
    return jsonify(file_scan.scan_all())


@app.route("/api/runs")
def list_runs():
    """실행별 로그 조회: 웹 시연 실행 폴더(s01_~s04_)와 폴더별 감염 의심 수."""
    return jsonify(file_scan.list_runs())


@app.route("/api/runs/<name>")
def run_detail(name):
    """실행별 상세: 실행 폴더 하나의 파일 전체."""
    data = file_scan.scan_run(name)
    if data is None:
        return jsonify({"error": "not found"}), 404
    return jsonify(data)


@app.route("/api/files/preview")
def file_preview():
    data = file_scan.preview(request.args.get("folder", ""), request.args.get("path", ""))
    if data is None:
        return jsonify({"error": "not found"}), 404
    return jsonify(data)


@app.route("/api/health")
def health():
    return jsonify({"ok": True, "llm": _llm_client is not None,
                    "model": OPENAI_MODEL if _llm_client else "local-rules",
                    "medium_timeout_sec": STAGE2_MEDIUM_TIMEOUT_SEC,
                    "high_threshold": STAGE2_HIGH_THRESHOLD,
                    "dyn_only_threshold": STAGE2_DYN_ONLY_HIGH_THRESHOLD})


@app.route("/api/system")
def system_status():
    data = sys_status.status()
    data["llm"] = {"connected": _llm_client is not None,
                   "model": OPENAI_MODEL if _llm_client else "local-rules"}
    return jsonify(data)


@app.route("/api/chat", methods=["POST"])
def chat():
    body = request.get_json(silent=True) or {}
    question = (body.get("message") or "").strip()
    history = body.get("history") or []
    if not question:
        return jsonify({"error": "message required"}), 400
    if len(question) > CHAT_MAX_QUESTION_CHARS:
        return jsonify({"error": f"질문은 {CHAT_MAX_QUESTION_CHARS}자 이하로 입력하세요."}), 413
    if not isinstance(history, list):
        history = []

    evs = _snapshot()
    context, summaries, docs = build_context(question, evs)
    sources = {
        "pids": [s["pid"] for s in summaries],
        "docs": [d["title"] for d in docs],
        "events": sum(s["count"] for s in summaries),
    }

    if _llm_client is None:
        return jsonify({"reply": local_analysis(question, evs), "mode": "local", "sources": sources})

    if not _chat_rate_ok():
        return jsonify({"error": f"AI 분석관 요청이 너무 많습니다 (분당 {CHAT_RATE_PER_MIN}회). 잠시 후 다시 시도하세요."}), 429

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "system", "content": RAG_INSTRUCTION.format(context=context)},
    ]
    for turn in history[-8:]:
        if not isinstance(turn, dict):
            continue
        role = turn.get("role")
        content = turn.get("content")
        if role in ("user", "assistant") and isinstance(content, str):
            messages.append({"role": role, "content": content[:CHAT_MAX_HISTORY_CHARS]})
    messages.append({"role": "user", "content": question})

    try:
        params = dict(model=OPENAI_MODEL, messages=messages, temperature=0.3, max_tokens=CHAT_MAX_TOKENS)
        try:
            resp = _llm_client.chat.completions.create(
                **params, **({"reasoning_effort": CHAT_REASONING} if CHAT_REASONING else {}))
        except Exception as e:  # 모델이 reasoning_effort 값을 지원하지 않으면 빼고 한 번 더
            if not CHAT_REASONING or "reasoning" not in str(e).lower():
                raise
            app.logger.warning("reasoning_effort=%s 미지원, 빼고 재시도: %s", CHAT_REASONING, e)
            resp = _llm_client.chat.completions.create(**params)
        choice = resp.choices[0]
        reply = choice.message.content or ""
        if choice.finish_reason == "length":
            reply += ("\n\n> 답변이 길이 제한(DASH_CHAT_MAX_TOKENS)에 걸려 잘렸습니다. "
                      "질문을 나누어 다시 물어보세요.")
        return jsonify({"reply": reply, "mode": "llm", "sources": sources})
    except Exception as e:  # LLM 장애 시에도 대시보드는 답을 주도록 로컬 분석으로 대체
        app.logger.warning("LLM 호출 실패: %s", e)
        reply = (f"> LLM 호출에 실패해 로컬 규칙 기반 분석으로 대체합니다. ({type(e).__name__})\n\n"
                 + local_analysis(question, evs))
        return jsonify({"reply": reply, "mode": "local", "sources": sources})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HoldFS EDR Dashboard server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()

    print(f"[DASHBOARD] http://{args.host}:{args.port}")
    print(f"[DASHBOARD] LLM: {'OpenAI ' + OPENAI_MODEL if _llm_client else '미연결 (로컬 규칙 기반 분석)'}")
    app.run(host=args.host, port=args.port, debug=False, threaded=True)
