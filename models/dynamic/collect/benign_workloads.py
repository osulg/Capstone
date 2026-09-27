"""
정상(benign) 워크로드 정의.

각 워크로드는 랜섬웨어와 표면적으로 닮은 정상 작업이다(대량 읽기/쓰기/삭제/
이름변경/압축 등). "이벤트가 많으면 악성"이라는 규칙이 무너지도록 일부러 넣는다.

- needs: 필요한 외부 실행 파일. 없으면 러너가 건너뛴다.
- seed(workdir, files, size_kb): 수집 시작 전에 입력 파일을 준비한다(추적 대상 아님).
- command(workdir, files, size_kb): 수집 대상으로 실제 실행할 argv를 돌려준다.

경로는 모두 workdir(마운트 안의 실행별 디렉터리) 기준 절대 경로다.
"""

import os
import shutil

TEXT_LINE = ("the quick brown fox jumps over the lazy dog " * 2 + "\n").encode()


def _write_text(path, size_kb):
    """압축·저엔트로피 파일. tar/gzip이 실제로 압축 작업을 하도록."""
    with open(path, "wb") as f:
        written = 0
        target = size_kb * 1024
        while written < target:
            f.write(TEXT_LINE)
            written += len(TEXT_LINE)


def _write_random(path, size_kb):
    """고엔트로피 파일. 정상 작업도 고엔트로피 데이터를 다룰 수 있음을 학습시킨다."""
    with open(path, "wb") as f:
        f.write(os.urandom(size_kb * 1024))


def _seed_files(workdir, files, size_kb, kind="text"):
    src = os.path.join(workdir, "src")
    os.makedirs(src, exist_ok=True)
    writer = _write_random if kind == "random" else _write_text
    for i in range(files):
        writer(os.path.join(src, f"file_{i:04d}.dat"), size_kb)
    return src


def _seed_tree(workdir, files, size_kb, depth=3):
    """디렉터리 깊이가 있는 트리. find/rsync류 재귀 순회를 닮게 한다."""
    src = os.path.join(workdir, "tree")
    cur = src
    for d in range(depth):
        cur = os.path.join(cur, f"lvl{d}")
    os.makedirs(cur, exist_ok=True)
    for i in range(files):
        _write_text(os.path.join(cur, f"file_{i:04d}.txt"), size_kb)
    return src


# ---- 개별 워크로드 -------------------------------------------------------- #

def _bulk_copy(workdir, files, size_kb):
    src = _seed_files(workdir, files, size_kb)
    return ["cp", "-r", src, os.path.join(workdir, "copy")]


def _bulk_copy_preserve(workdir, files, size_kb):
    src = _seed_files(workdir, files, size_kb)
    return ["cp", "-rp", src, os.path.join(workdir, "copyp")]


def _bulk_move(workdir, files, size_kb):
    src = _seed_files(workdir, files, size_kb)
    return ["sh", "-c", f'mv "{src}"/* "{workdir}"/']


def _bulk_delete(workdir, files, size_kb):
    src = _seed_files(workdir, files, size_kb)
    return ["find", src, "-type", "f", "-delete"]


def _rename_ext(workdir, files, size_kb):
    """확장자 일괄 변경 — 랜섬웨어의 대표 신호를 정상 작업으로 재현."""
    src = _seed_files(workdir, files, size_kb)
    return ["sh", "-c", f'for f in "{src}"/*.dat; do mv "$f" "$f.bak"; done']


def _sed_inplace(workdir, files, size_kb):
    src = _seed_files(workdir, files, size_kb)
    return ["sh", "-c", f'find "{src}" -type f -exec sed -i "s/fox/cat/g" {{}} +']


def _read_all(workdir, files, size_kb):
    src = _seed_files(workdir, files, size_kb)
    return ["sh", "-c", f'find "{src}" -type f -exec cat {{}} + > /dev/null']


def _tar_create(workdir, files, size_kb):
    src = _seed_files(workdir, files, size_kb)
    return ["tar", "cf", os.path.join(workdir, "archive.tar"), "-C", src, "."]


def _tar_gzip(workdir, files, size_kb):
    src = _seed_files(workdir, files, size_kb)
    return ["tar", "czf", os.path.join(workdir, "archive.tgz"), "-C", src, "."]


def _tar_extract(workdir, files, size_kb):
    src = _seed_files(workdir, files, size_kb)
    tar = os.path.join(workdir, "seed.tar")
    os.system(f'tar cf "{tar}" -C "{src}" .')
    out = os.path.join(workdir, "extracted")
    os.makedirs(out, exist_ok=True)
    return ["tar", "xf", tar, "-C", out]


def _gzip_each(workdir, files, size_kb):
    src = _seed_files(workdir, files, size_kb)
    return ["sh", "-c", f'gzip "{src}"/*.dat']


def _zip_archive(workdir, files, size_kb):
    src = _seed_files(workdir, files, size_kb)
    return ["sh", "-c", f'cd "{src}" && zip -q -r "{workdir}/archive.zip" .']


def _random_bulk_write(workdir, files, size_kb):
    # 고엔트로피 대량 쓰기(정상). 씨앗 없이 새로 쓴다.
    os.makedirs(os.path.join(workdir, "out"), exist_ok=True)
    inner = (
        "import os,sys;"
        "d=sys.argv[1];n=int(sys.argv[2]);k=int(sys.argv[3]);"
        "[open(os.path.join(d,'r%04d.bin'%i),'wb').write(os.urandom(k*1024)) for i in range(n)]"
    )
    return ["python3", "-c", inner, os.path.join(workdir, "out"), str(files), str(size_kb)]


def _git_checkout(workdir, files, size_kb):
    """git이 워킹트리를 대량으로 갈아끼우는 작업(체크아웃)."""
    repo = os.path.join(workdir, "repo")
    src = _seed_files(repo, files, size_kb)
    env = 'GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@t GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@t'
    script = (
        f'cd "{repo}" && git init -q && {env} git add -A && {env} git commit -q -m a && '
        f'{env} git checkout -q -b other && rm -rf src/* && '
        f'{env} git commit -qam b && {env} git checkout -q master 2>/dev/null || '
        f'{env} git checkout -q main'
    )
    _ = src
    return ["sh", "-c", script]


def _sqlite_bulk(workdir, files, size_kb):
    """파이썬 sqlite3로 대량 삽입 — DB 파일에 반복 쓰기."""
    n = max(files * 200, 1000)
    inner = (
        "import sqlite3,sys,os;"
        "db=os.path.join(sys.argv[1],'data.db');c=sqlite3.connect(db);"
        "c.execute('create table t(id integer primary key, v text)');"
        "c.executemany('insert into t(v) values(?)',[('x'*200,) for _ in range(int(sys.argv[2]))]);"
        "c.commit();c.execute('delete from t where id%2=0');c.commit();"
        "c.execute('vacuum');c.close()"
    )
    return ["python3", "-c", inner, workdir, str(n)]


# name -> (needs, command_builder)
WORKLOADS = {
    "bulk_copy":        (["cp"], _bulk_copy),
    "bulk_copy_p":      (["cp"], _bulk_copy_preserve),
    "bulk_move":        (["mv"], _bulk_move),
    "bulk_delete":      (["find"], _bulk_delete),
    "rename_ext":       (["mv"], _rename_ext),
    "sed_inplace":      (["find", "sed"], _sed_inplace),
    "read_all":         (["find", "cat"], _read_all),
    "tar_create":       (["tar"], _tar_create),
    "tar_gzip":         (["tar", "gzip"], _tar_gzip),
    "tar_extract":      (["tar"], _tar_extract),
    "gzip_each":        (["gzip"], _gzip_each),
    "zip_archive":      (["zip"], _zip_archive),
    "random_write":     (["python3"], _random_bulk_write),
    "git_checkout":     (["git"], _git_checkout),
    "sqlite_bulk":      (["python3"], _sqlite_bulk),
}


def available(names=None):
    """실행 가능한 워크로드만 (needs 도구가 전부 있는 것)."""
    result = {}
    for name, (needs, builder) in WORKLOADS.items():
        if names and name not in names:
            continue
        if all(shutil.which(t) for t in needs):
            result[name] = builder
    return result


def missing(names=None):
    result = {}
    for name, (needs, _b) in WORKLOADS.items():
        if names and name not in names:
            continue
        absent = [t for t in needs if not shutil.which(t)]
        if absent:
            result[name] = absent
    return result
