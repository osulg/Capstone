"""
CCCV EDR Dashboard 서버

- 에이전트(agent.py)가 GuardFS 정책 수행 결과를 JSON으로 POST /api/events 에 전송
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

from flask import Flask, jsonify, render_template, request

try:
    from dashboard.rag import build_context, local_analysis
    from dashboard import files as file_scan
except ImportError:  # python dashboard/server.py 로 직접 실행한 경우
    from rag import build_context, local_analysis
    import files as file_scan

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None

app = Flask(__name__)

MAX_EVENTS = 5000
events = []  # in-memory log store
_events_lock = threading.Lock()
_next_id = 1
# 서버 재시작/로그 비우기 시 바뀌는 값. 대시보드는 이 값이 바뀌면 테이블을 다시 받는다.
_generation = int(time.time() * 1000)

OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
_llm_client = None
if OpenAI is not None and os.environ.get("OPENAI_API_KEY"):
    _llm_client = OpenAI()

SYSTEM_PROMPT = """당신은 엔드포인트 보안 분석 전문가입니다. CCCV EDR 시스템의 보안 이벤트 로그를 분석하여 보안팀에게 인사이트를 제공합니다.

CCCV 시스템 개요:
- FUSE 기반 실시간 파일 보호 정책 엔진
- Stage1: 엔트로피 탐지 / 삭제 빈도 / 허니팟 접근 → score ≥ 1이면 ML 평가
- Stage2: 동적 RF + 정적 RF 앙상블 (가중치 0.5/0.5)
- MEDIUM (score 0.3~0.82): write 버퍼링 + 1초 주기 재평가
- HIGH (score ≥ 0.82): write/rename/unlink/truncate 차단 + SIGSTOP

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

RAG_INSTRUCTION = """아래는 질문과 관련해 검색된 CCCV EDR 이벤트 로그와 참고 지식입니다.
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
        try:
            ts = time.mktime(time.strptime(ev["time"], "%Y-%m-%d %H:%M:%S"))
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
    return render_template("index.html")


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


@app.route("/api/files/preview")
def file_preview():
    data = file_scan.preview(request.args.get("folder", ""), request.args.get("path", ""))
    if data is None:
        return jsonify({"error": "not found"}), 404
    return jsonify(data)


@app.route("/api/health")
def health():
    return jsonify({"ok": True, "llm": _llm_client is not None,
                    "model": OPENAI_MODEL if _llm_client else "local-rules"})


@app.route("/api/chat", methods=["POST"])
def chat():
    body = request.get_json(silent=True) or {}
    question = (body.get("message") or "").strip()
    history = body.get("history") or []
    if not question:
        return jsonify({"error": "message required"}), 400

    evs = _snapshot()
    context, summaries, docs = build_context(question, evs)
    sources = {
        "pids": [s["pid"] for s in summaries],
        "docs": [d["title"] for d in docs],
        "events": sum(s["count"] for s in summaries),
    }

    if _llm_client is None:
        return jsonify({"reply": local_analysis(question, evs), "mode": "local", "sources": sources})

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "system", "content": RAG_INSTRUCTION.format(context=context)},
    ]
    for turn in history[-8:]:
        role = turn.get("role")
        content = turn.get("content")
        if role in ("user", "assistant") and isinstance(content, str):
            messages.append({"role": role, "content": content[:4000]})
    messages.append({"role": "user", "content": question})

    try:
        resp = _llm_client.chat.completions.create(
            model=OPENAI_MODEL,
            messages=messages,
            temperature=0.3,
        )
        reply = resp.choices[0].message.content or ""
        return jsonify({"reply": reply, "mode": "llm", "sources": sources})
    except Exception as e:  # LLM 장애 시에도 대시보드는 답을 주도록 로컬 분석으로 대체
        app.logger.warning("LLM 호출 실패: %s", e)
        reply = (f"> LLM 호출에 실패해 로컬 규칙 기반 분석으로 대체합니다. ({type(e).__name__})\n\n"
                 + local_analysis(question, evs))
        return jsonify({"reply": reply, "mode": "local", "sources": sources})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CCCV EDR Dashboard server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()

    print(f"[DASHBOARD] http://{args.host}:{args.port}")
    print(f"[DASHBOARD] LLM: {'OpenAI ' + OPENAI_MODEL if _llm_client else '미연결 (로컬 규칙 기반 분석)'}")
    app.run(host=args.host, port=args.port, debug=False, threaded=True)
