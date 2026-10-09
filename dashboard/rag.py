"""
CCCV EDR 대시보드 - RAG(Retrieval-Augmented Generation) 모듈

LLM에 넘길 근거(context)를 두 갈래로 검색한다.

1. 이벤트 검색: 질문에 언급된 PID / 파일명을 기준으로 관련 이벤트를 찾고,
   PID 단위 요약(격상 경위, 동작/결과 통계, 대상 파일)을 만든다.
2. 지식 검색: GuardFS 정책 / 격상 사유 / MITRE ATT&CK / 랜섬웨어 패밀리
   지식 문서 중 질문과 이벤트에 가장 관련 있는 문서를 키워드 점수로 고른다.

외부 의존성 없이 동작하도록 벡터 DB 대신 키워드 기반 검색을 사용한다.
LLM API 키가 없을 때 쓰는 규칙 기반 로컬 분석기(local_analysis)도 포함한다.
"""

from __future__ import annotations

import os
import re
from collections import Counter, OrderedDict

# --------------------------------------------------------------------------- #
# 지식 베이스
# --------------------------------------------------------------------------- #

KNOWLEDGE_BASE = [
    {
        "id": "policy-stage1",
        "title": "Stage1 경량 탐지",
        "keywords": ["stage1", "suspicious", "honeypot", "허니팟", "entropy", "엔트로피",
                     "extchange", "확장자", "stat_anomaly", "sampling", "탐지기"],
        "text": (
            "Stage1은 FUSE 이벤트마다 경량 탐지기를 돌린다. HoneypotDetector(허니팟 파일 접근), "
            "ExtChangeDetector(짧은 시간 내 확장자 변경 반복), EntropyDetector / EntropyBurstDetector "
            "(고엔트로피 write, 5초 창 안에 서로 다른 파일 3개 이상·5회 이상의 고엔트로피 write), "
            "EntropyDeltaDetector(원본 대비 엔트로피 급증), stat_anomaly(1초 창의 write·삭제 빈도 이상), "
            "stage1_sampling(비신뢰 경로 신규 PID 15% 확률 샘플링) 중 하나라도 걸리면 PID는 "
            "LOW → SUSPICIOUS가 되고 Stage2 ML 평가 큐에 들어간다."
        ),
    },
    {
        "id": "policy-stage2",
        "title": "Stage2 ML 평가와 격상 기준",
        "keywords": ["stage2", "ml", "score", "점수", "dyn", "stat", "동적", "정적", "rf",
                     "ml_score", "dyn_only", "watch", "reeval", "재평가", "격상", "threshold"],
        "text": (
            "Stage2는 동적 RF(PID 단위 22개 FUSE 행동 피처)와 정적 RF(실행 파일 byte 3-gram)를 "
            "0.5/0.5 가중합한다. score ≥ 0.82 이거나 동적 점수 단독 ≥ 0.5면 HIGH, "
            "0.3 ≤ score < 0.82면 MEDIUM, 그 미만이면 SUSPICIOUS 상태로 10초간 1초마다 재채점(WATCH)한다. "
            "격상 사유 문자열: ml_score=X(최초 평가 가중합), dyn_only=X(동적 단독 확신), "
            "watch_score / watch_dyn_only(관찰 창 재채점), reeval_score / reeval_dyn_only(MEDIUM 1초 주기 재평가). "
            "동적 단독 규칙은 python3 같은 양성 인터프리터로 실행되는 스크립트형 랜섬웨어처럼 정적 점수가 "
            "낮게 나오는 경우를 잡기 위한 것이다."
        ),
    },
    {
        "id": "policy-medium",
        "title": "MEDIUM 정책 (버퍼링·지연 확정)",
        "keywords": ["medium", "buffered", "버퍼", "staged", "commit", "커밋", "drop", "buffer_dropped",
                     "restored", "confirmed", "unlink", "스테이징", "지연", "untrusted", "trust"],
        "text": (
            "MEDIUM 프로세스의 write는 디스크에 바로 쓰이지 않고 메모리 버퍼에 보관된다(BUFFERED). "
            "unlink는 실제 삭제 대신 스테이징 디렉터리로 이동한다(STAGED). 10초 동안 재평가해 정상이면 "
            "버퍼를 커밋(COMMIT SUCCESS)하고 삭제를 확정(CONFIRMED)하며, HIGH로 격상되면 버퍼를 모두 버리고"
            "(DROP / BUFFER_DROPPED) 스테이징된 원본을 복원(RESTORED)한다. 즉 BUFFER_DROPPED는 "
            "악성 write가 원본에 반영되지 않았다는 의미다. 비신뢰 경로(/tmp, 다운로드 등)에서 실행된 "
            "프로세스는 ML 판정 전에도 선제적으로 MEDIUM(untrusted_origin) 취급된다."
        ),
    },
    {
        "id": "policy-medium-rules",
        "title": "MEDIUM 중 즉시 HIGH 격상 규칙",
        "keywords": ["magic", "magic_mismatch", "high_entropy_write", "buffer_limit", "global_buffer",
                     "structural", "구조", "escalated_to_high", "확장자 그룹", "ext_group"],
        "text": (
            "MEDIUM 상태에서 다음이 관찰되면 Stage2 재평가를 기다리지 않고 즉시 HIGH로 격상한다. "
            "magic_mismatch: 확장자와 파일 헤더 magic number가 불일치(예: .pdf인데 %PDF- 아님). "
            "high_entropy_write(ext=그룹): 확장자 그룹별 엔트로피 임계값 초과 write(암호화 의심). "
            "buffer_limit_exceeded: PID·확장자 그룹별 버퍼 상한 초과. "
            "global_buffer_limit_exceeded: 시스템 전역 버퍼 200MB 초과(DoS 시도). "
            "magic_mismatch_reeval / magic_mismatch_on_commit / structural_check_failed: 재평가 또는 "
            "커밋 직전 구조 검증(ZIP 목차, PDF 트레일러, SQLite 헤더 등) 실패."
        ),
    },
    {
        "id": "policy-high",
        "title": "HIGH 정책 (차단·정지)",
        "keywords": ["high", "blocked", "차단", "sigstop", "suspend", "정지", "rename", "truncate",
                     "delete", "mkdir", "rmdir", "o_trunc"],
        "text": (
            "HIGH 프로세스는 write / rename / unlink(DELETE) / truncate / O_TRUNC open / mkdir / rmdir가 "
            "모두 차단(BLOCKED)되고 SIGSTOP으로 일시정지된다. 차단된 write는 호출자에게는 성공으로 "
            "응답하지만 실제 디스크에는 기록되지 않는다. 프로세스는 종료되지 않고 정지 상태이므로 "
            "보안팀이 메모리 덤프·포렌식 후 kill -9로 종료하거나 오탐이면 kill -CONT로 재개할 수 있다."
        ),
    },
    {
        "id": "mitre-t1486",
        "title": "T1486 Data Encrypted for Impact",
        "keywords": ["t1486", "암호화", "encrypt", "entropy", "엔트로피", "write", "high_entropy",
                     "ransomware", "랜섬웨어", "확장자"],
        "text": (
            "T1486: 공격자가 시스템의 데이터를 암호화해 가용성을 해치는 기법. 다수 파일에 대한 연속적인 "
            "고엔트로피 write, 원본 덮어쓰기, 암호화 후 확장자 변경(.locked, .enc 등)이 대표 지표다."
        ),
    },
    {
        "id": "mitre-t1485",
        "title": "T1485 Data Destruction",
        "keywords": ["t1485", "삭제", "delete", "unlink", "destruction", "파괴", "staged", "truncate"],
        "text": (
            "T1485: 데이터를 삭제·덮어써 복구 불가능하게 만드는 기법. 랜섬웨어는 암호화본을 만든 뒤 원본을 "
            "unlink 하거나 truncate 하는 경우가 많다. GuardFS의 DELETE BLOCKED, UNLINK STAGED, "
            "TRUNCATE BLOCKED 이벤트가 이에 해당한다."
        ),
    },
    {
        "id": "mitre-t1083",
        "title": "T1083 File and Directory Discovery",
        "keywords": ["t1083", "discovery", "탐색", "honeypot", "허니팟", "readdir", "디렉터리"],
        "text": (
            "T1083: 암호화 대상을 찾기 위해 파일·디렉터리를 순회하는 기법. 사람이 열 일이 없는 허니팟 "
            "파일 접근, 짧은 시간 내 다수 디렉터리·파일을 순차적으로 건드리는 패턴이 지표다."
        ),
    },
    {
        "id": "mitre-t1036",
        "title": "T1036 Masquerading",
        "keywords": ["t1036", "masquerading", "위장", "magic", "확장자", "extension", "python3", "인터프리터"],
        "text": (
            "T1036: 파일·프로세스를 정상처럼 보이게 위장하는 기법. 확장자와 실제 내용(magic number)이 다른 "
            "파일, victim_1.txt처럼 정상 이름을 유지한 채 내용만 암호화하는 경우, 정상 인터프리터"
            "(python3, bash)를 이용한 스크립트형 실행이 해당될 수 있다."
        ),
    },
    {
        "id": "mitre-t1490",
        "title": "T1490 Inhibit System Recovery",
        "keywords": ["t1490", "복구", "백업", "shadow", "snapshot", "rmdir", "recovery"],
        "text": (
            "T1490: 백업·스냅샷·복구 지점을 삭제해 복구를 방해하는 기법. 백업 디렉터리 대량 삭제(rmdir), "
            "vssadmin / btrfs snapshot 삭제 시도 등이 지표다."
        ),
    },
    {
        "id": "family",
        "title": "랜섬웨어 패밀리 행위 특성",
        "keywords": ["패밀리", "family", "lockbit", "wannacry", "ryuk", "conti", "blackcat", "alphv",
                     "revil", "유사", "변종", "python", "스크립트"],
        "text": (
            "LockBit: 매우 빠른 멀티스레드 부분 암호화(파일 앞부분만 암호화), 확장자 변경 후 랜섬노트 생성. "
            "WannaCry: .WNCRY 확장자, 원본 삭제 후 암호화본 생성, 웜 전파. "
            "Ryuk / Conti: 고가치 문서·DB 우선 암호화, 백업 삭제(T1490), 다수 스레드. "
            "BlackCat(ALPHV): Rust 기반, 설정에 따라 확장자 변경, Linux/ESXi 변종 존재. "
            "REvil: 확장자 무작위화, 랜섬노트. "
            "Python 기반 스크립트형 랜섬웨어(PoC·교육용 변종): 단일 프로세스가 순차적으로 파일을 열어 "
            "전체를 덮어쓰기 암호화하며 확장자를 유지하거나 단순 변경하는 경우가 많다. "
            "실행 파일이 python3이면 정적 분석 점수는 낮고 동적 행위 점수가 높게 나오는 경향이 있다."
        ),
    },
    {
        "id": "response",
        "title": "대응 절차",
        "keywords": ["대응", "조치", "response", "격리", "kill", "포렌식", "복구", "모니터링", "권고"],
        "text": (
            "1) HIGH PID는 SIGSTOP 상태이므로 /proc/<pid>/exe, cmdline, 부모 PID(ppid)를 먼저 수집한다. "
            "2) 메모리 덤프(gcore) 후 kill -9로 종료하고 부모 프로세스·지속성(cron, systemd) 확인. "
            "3) 실행 파일 해시를 추출해 위협 인텔리전스와 대조. "
            "4) MEDIUM 중 버퍼링된 write는 DROP되어 원본이 보존되므로 underlay 파일 무결성을 확인한다. "
            "5) 같은 실행 파일·부모에서 파생된 다른 PID를 추적하고, 네트워크 격리 여부를 판단한다."
        ),
    },
]

_TOKEN_RE = re.compile(r"[0-9A-Za-z가-힣_.&]+")


def _tokens(text: str) -> set[str]:
    return {t.lower() for t in _TOKEN_RE.findall(text or "")}


def search_knowledge(query_text: str, top_k: int = 4) -> list[dict]:
    """키워드 겹침 점수로 지식 문서를 고른다."""
    q = (query_text or "").lower()
    q_tokens = _tokens(q)
    scored = []
    for doc in KNOWLEDGE_BASE:
        score = 0
        for kw in doc["keywords"]:
            kw_l = kw.lower()
            if kw_l in q_tokens:
                score += 2
            elif kw_l in q:
                score += 1
        if score:
            scored.append((score, doc))
    scored.sort(key=lambda x: x[0], reverse=True)
    return [d for _, d in scored[:top_k]]


# --------------------------------------------------------------------------- #
# 이벤트 검색 / 요약
# --------------------------------------------------------------------------- #

LEVEL_RANK = {"HIGH": 3, "MEDIUM": 2, "SUSPICIOUS": 1, "LOW": 0}


def find_focus(question: str, events: list[dict], max_pids: int = 5) -> list[int]:
    """질문에 언급된 PID·파일명으로 분석 대상 PID를 정한다."""
    known_pids = OrderedDict()
    for ev in events:
        known_pids.setdefault(ev["pid"], None)

    mentioned = [int(n) for n in re.findall(r"\d{2,8}", question or "") if int(n) in known_pids]
    if mentioned:
        return list(dict.fromkeys(mentioned))[:max_pids]

    # 파일명 언급 (예: victim_6.txt)
    names = re.findall(r"[\w\-.]+\.\w{1,8}", question or "")
    if names:
        hit = [ev["pid"] for ev in events
               if any(n in (ev.get("target") or "") for n in names)]
        if hit:
            return list(dict.fromkeys(hit))[:max_pids]

    # 언급이 없으면 위험도 → 이벤트 수 순으로 상위 PID
    rank = {}
    for ev in events:
        r = rank.setdefault(ev["pid"], [0, 0])
        r[0] = max(r[0], LEVEL_RANK.get(ev["level"], 0))
        r[1] += 1
    return sorted(rank, key=lambda p: (rank[p][0], rank[p][1]), reverse=True)[:max_pids]


def summarize_pid(pid: int, events: list[dict]) -> dict:
    evs = sorted((e for e in events if e["pid"] == pid), key=lambda e: e["ts"])
    if not evs:
        return {}
    process = next((e["process"] for e in evs if e.get("process") and e["process"] != "-"), "-")
    max_level = max(evs, key=lambda e: LEVEL_RANK.get(e["level"], 0))["level"]
    targets = list(dict.fromkeys(e["target"] for e in evs if e.get("target")))
    escalations = [e for e in evs if e["action"] in ("ESCALATE", "STATE")
                   or e["result"] in ("ESCALATED_TO_HIGH",)]
    reasons = list(dict.fromkeys(e["reason"] for e in evs if e.get("reason")))
    exts = Counter(os.path.splitext(t)[1].lower() or "(없음)" for t in targets)
    return {
        "pid": pid,
        "process": process,
        "max_level": max_level,
        "first": evs[0]["time"],
        "last": evs[-1]["time"],
        "count": len(evs),
        "actions": Counter(e["action"] for e in evs),
        "results": Counter(e["result"] for e in evs),
        "targets": targets,
        "extensions": exts,
        "escalations": escalations,
        "reasons": reasons,
        "events": evs,
    }


def _fmt_counter(c: Counter) -> str:
    return ", ".join(f"{k}×{v}" for k, v in c.most_common()) or "-"


def build_context(question: str, events: list[dict], max_raw: int = 60) -> tuple[str, list[dict], list[dict]]:
    """LLM 프롬프트에 넣을 RAG 컨텍스트 문자열과 사용한 요약/문서를 반환한다."""
    if not events:
        docs = search_knowledge(question)
        ctx = "## 수신된 이벤트\n현재 수신된 EDR 이벤트가 없습니다.\n"
        ctx += _docs_block(docs)
        return ctx, [], docs

    focus = find_focus(question, events)
    summaries = [summarize_pid(p, events) for p in focus]

    total = Counter(e["level"] for e in events)
    lines = [
        "## 전체 현황",
        f"- 전체 이벤트 {len(events)}건 (HIGH {total.get('HIGH', 0)}, MEDIUM {total.get('MEDIUM', 0)})",
        f"- 관측된 PID: {', '.join(str(p) for p in dict.fromkeys(e['pid'] for e in events))}",
        "",
        "## 분석 대상 PID 요약",
    ]
    for s in summaries:
        lines += [
            f"### PID {s['pid']} ({s['process']}) — 최고 위험도 {s['max_level']}",
            f"- 기간: {s['first']} ~ {s['last']}, 이벤트 {s['count']}건",
            f"- 동작: {_fmt_counter(s['actions'])}",
            f"- 결과: {_fmt_counter(s['results'])}",
            f"- 대상 파일({len(s['targets'])}개): {', '.join(s['targets'][:15])}",
            f"- 확장자 분포: {_fmt_counter(s['extensions'])}",
            f"- 탐지/격상 사유: {' | '.join(s['reasons'][:12]) or '-'}",
        ]
        if s["escalations"]:
            lines.append("- 상태 전이 타임라인:")
            for e in s["escalations"]:
                lines.append(f"  - {e['time']} {e['result']} ({e['reason'] or '-'})")
        lines.append("")

    lines.append("## 관련 원본 이벤트 (시간순)")
    raw = [e for s in summaries for e in s["events"]]
    raw.sort(key=lambda e: e["ts"])
    for e in raw[-max_raw:]:
        lines.append(
            f"- {e['time']} | {e['level']} | pid={e['pid']} | {e['process'] or '-'} | "
            f"{e['action']} | {e['result']} | {e['target'] or '-'} | {e['reason'] or '-'}"
        )

    kb_query = question + " " + " ".join(
        " ".join(s["reasons"]) + " " + " ".join(s["actions"]) + " " + " ".join(s["results"])
        for s in summaries
    )
    docs = search_knowledge(kb_query, top_k=5)
    ctx = "\n".join(lines) + "\n" + _docs_block(docs)
    return ctx, summaries, docs


def _docs_block(docs: list[dict]) -> str:
    if not docs:
        return ""
    out = ["", "## 참고 지식 (검색됨)"]
    for d in docs:
        out.append(f"### {d['title']}\n{d['text']}")
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------- #
# LLM 미연결 시 규칙 기반 로컬 분석
# --------------------------------------------------------------------------- #

_REASON_TABLE = {
    "magic_mismatch_on_commit": "커밋 직전 magic number 불일치",
    "magic_mismatch_reeval": "재평가 중 버퍼 헤더 구조 깨짐",
    "magic_mismatch": "확장자와 파일 헤더(magic number) 불일치",
    "structural_check_failed": "커밋 직전 내부 구조 검증 실패",
    "global_buffer_limit_exceeded": "시스템 전역 버퍼 상한 초과",
    "buffer_limit_exceeded": "확장자 그룹별 버퍼 상한 초과",
    "high_entropy_write": "확장자 그룹 기준 고엔트로피 write(암호화 의심)",
    "untrusted_origin": "비신뢰 실행 경로에서 실행되어 선제 MEDIUM",
    "HoneypotDetector": "Stage1 허니팟 파일 접근 탐지",
    "ExtChangeDetector": "Stage1 확장자 변경 반복 탐지",
    "EntropyBurstDetector": "Stage1 짧은 시간 내 다수 파일 고엔트로피 write 탐지",
    "EntropyDeltaDetector": "Stage1 원본 대비 엔트로피 급증 탐지",
    "EntropyDetector": "Stage1 고엔트로피 write 탐지",
    "stat_anomaly": "Stage1 write/삭제 빈도 통계 이상",
    "stage1_sampling": "Stage1 비신뢰 경로 신규 프로세스 샘플링",
}


def _reason_ko(reason: str) -> str:
    """격상 사유 문자열을 사람이 읽을 수 있는 설명으로 바꾼다 (여러 개면 모두)."""
    r = reason or ""
    parts = []
    m = re.search(r"(ml_score|watch_score|reeval_score)=([\d.]+)", r)
    if m:
        where = {"ml_score": "최초 Stage2 평가", "watch_score": "관찰 창 재채점",
                 "reeval_score": "MEDIUM 재평가"}[m.group(1)]
        parts.append(f"{where}에서 ML 가중합 점수 {m.group(2)}가 HIGH 임계값(0.82) 이상")
    m = re.search(r"(dyn_only|watch_dyn_only|reeval_dyn_only)=([\d.]+)", r)
    if m:
        parts.append(f"동적(행동) 모델 단독 점수 {m.group(2)}가 단독 HIGH 임계값(0.5) 이상")
    m = re.search(r"(Stage2 최초 평가|관찰 창 재채점) score=([\d.]+)", r)
    if m:
        parts.append(f"{m.group(1)} 점수 {m.group(2)} (MEDIUM 구간 0.3 ~ 0.82)")
    matched = []
    for k, v in _REASON_TABLE.items():
        # magic_mismatch_reeval 이 magic_mismatch 로, global_buffer_... 가 buffer_... 로
        # 중복 매칭되지 않도록 이미 매칭된 더 긴 키에 포함된 키는 건너뛴다.
        if k in r and not any(k in mk for mk in matched):
            matched.append(k)
            parts.append(v)
    return ", ".join(parts) or r


def _mitre_for(s: dict) -> list[tuple[str, str]]:
    acts, res = s["actions"], s["results"]
    reasons = " ".join(s["reasons"])
    out = []
    if acts.get("WRITE") or "entropy" in reasons.lower():
        out.append(("T1486 Data Encrypted for Impact",
                    f"WRITE {acts.get('WRITE', 0)}건이 {len(s['targets'])}개 파일에 연속 발생"
                    + (", 고엔트로피 탐지" if "ntropy" in reasons else "")))
    if acts.get("DELETE") or acts.get("UNLINK") or any(a.startswith("TRUNCATE") for a in acts):
        out.append(("T1485 Data Destruction", "원본 파일 삭제/절단 시도 관찰"))
    if len(s["targets"]) >= 3 or "Honeypot" in reasons:
        out.append(("T1083 File and Directory Discovery",
                    "다수 파일을 순차적으로 탐색·접근" + (" (허니팟 접근 포함)" if "Honeypot" in reasons else "")))
    if "magic" in reasons or "ExtChange" in reasons or acts.get("RENAME"):
        out.append(("T1036 Masquerading", "확장자·헤더 불일치 또는 확장자 변경으로 파일 위장"))
    elif s["targets"] and acts.get("WRITE"):
        out.append(("T1036 Masquerading", "정상 파일명을 유지한 채 내용만 변조했을 가능성"))
    if acts.get("RMDIR"):
        out.append(("T1490 Inhibit System Recovery", "디렉터리 삭제 시도(백업 삭제 가능성)"))
    return out


def local_analysis(question: str, events: list[dict]) -> str:
    """LLM 없이 이벤트 통계만으로 보고서를 만든다."""
    if not events:
        return ("현재 수신된 EDR 이벤트가 없습니다.\n\n"
                "에이전트(`dashboard/agent.py`)를 실행하거나 `--demo` 옵션으로 샘플 이벤트를 보내 보세요.")

    focus = find_focus(question, events, max_pids=3)
    q = (question or "").lower()
    want_mitre = "att&ck" in q or "mitre" in q or "매핑" in q
    want_resp = "대응" in q or "조치" in q or "권고" in q
    want_family = "패밀리" in q or "family" in q or "유사" in q
    want_all = not (want_mitre or want_resp or want_family)

    out = []
    for pid in focus:
        s = summarize_pid(pid, events)
        out.append(f"PID **{pid}** ({s['process']})에 대한 분석 결과는 다음과 같습니다.\n")

        if want_all:
            out.append("### 공격 진행 경위 분석")
            step = 1
            writes = [e for e in s["events"] if e["action"] == "WRITE"]
            for esc in s["escalations"]:
                out.append(f"{step}. **{esc['result']} 격상**: {esc['time']} — {_reason_ko(esc['reason'])}.")
                step += 1
            buffered = [e for e in writes if e["result"] == "BUFFERED"]
            if buffered:
                names = ", ".join(os.path.basename(e["target"]) for e in buffered[:6])
                out.append(f"{step}. **버퍼링(MEDIUM)**: {buffered[0]['time']}부터 {buffered[-1]['time']}까지 "
                           f"{len(buffered)}건의 WRITE가 버퍼에 보관되었습니다 ({names}). "
                           "디스크에는 아직 반영되지 않았습니다.")
                step += 1
            for e in s["events"]:
                if e["result"] == "BLOCKED":
                    out.append(f"{step}. **차단(HIGH)**: {e['time']} `{os.path.basename(e['target'] or '-')}`에 대한 "
                               f"{e['action']}가 차단되었습니다. 사유: {_reason_ko(e['reason'])}.")
                    step += 1
                    break
            drops = [e for e in s["events"] if e["result"] == "BUFFER_DROPPED"]
            if drops:
                out.append(f"{step}. **버퍼 드롭**: {drops[0]['time']} HIGH 격상과 함께 버퍼링된 write가 폐기되어 "
                           "원본 파일이 보존되었습니다.")
                step += 1
            if step == 1:
                out.append(f"1. {s['first']} ~ {s['last']} 동안 {s['count']}건의 이벤트 "
                           f"({_fmt_counter(s['actions'])})가 관찰되었습니다.")
            out.append("")

        if want_all or want_mitre:
            out.append("### MITRE ATT&CK 기법 매핑")
            for tid, why in _mitre_for(s):
                out.append(f"- **{tid}**: {why}")
            out.append("")

        if want_all or want_family:
            out.append("### 랜섬웨어 패밀리 유사도")
            if s["process"] in ("python3", "python", "bash", "sh", "perl", "node"):
                out.append(f"- 실행 주체가 인터프리터(`{s['process']}`)이며 단일 프로세스가 파일을 순차 암호화하는 패턴으로, "
                           "**Python 기반 스크립트형 랜섬웨어(PoC/교육용 변종)**와 가장 유사합니다.")
            else:
                out.append("- 단일 프로세스의 순차적 파일 변조 패턴으로 LockBit / Ryuk 계열의 초기 암호화 단계와 유사할 수 있으나, "
                           "확장자 변경·랜섬노트가 관찰되지 않아 특정 패밀리로 단정하기 어렵습니다.")
            out.append("")

        if want_all or want_resp:
            out.append("### 즉각 대응 방안")
            if s["max_level"] == "HIGH":
                out.append(f"1. PID {pid}는 SIGSTOP 상태입니다. `ls -l /proc/{pid}/exe`, `cat /proc/{pid}/cmdline`로 실행 정보를 수집하세요.")
                out.append(f"2. 필요 시 `gcore {pid}`로 메모리를 덤프한 뒤 `kill -9 {pid}`로 종료하세요.")
            else:
                out.append(f"1. PID {pid}는 MEDIUM 상태로 write가 버퍼링 중입니다. 재평가 결과를 주시하세요.")
            out.append("3. 대상 파일의 underlay 원본 무결성을 확인하세요 (버퍼 드롭 시 원본 보존).")
            out.append("4. 부모 프로세스와 동일 실행 파일에서 파생된 다른 PID를 추적하세요.")
            out.append("")
            out.append("### 추가 모니터링 권고")
            out.append("- 동일 사용자 세션의 신규 python3/bash 프로세스 파일 접근 패턴")
            out.append("- 허니팟 디렉터리 접근 및 확장자 변경 이벤트")
            out.append("")

    return "\n".join(out).strip()
