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
    return ["sh", "-c", f'gzip -f "{src}"/*.dat']


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


# ---- 추가 워크로드 (실제 리눅스 프로그램, 정상 다양성 확대) ------------------ #

def _bzip2_each(workdir, files, size_kb):
    src = _seed_files(workdir, files, size_kb)
    return ["sh", "-c", f'bzip2 -f "{src}"/*.dat']


def _xz_each(workdir, files, size_kb):
    src = _seed_files(workdir, files, size_kb)
    return ["sh", "-c", f'xz -f "{src}"/*.dat']


def _zstd_each(workdir, files, size_kb):
    src = _seed_files(workdir, files, size_kb)
    return ["sh", "-c", f'zstd -f -q --rm "{src}"/*.dat']


def _gpg_symmetric(workdir, files, size_kb):
    """정상 대칭 암호화 — 고엔트로피 출력이 정상 작업에서도 나옴을 학습(핵심 대조군)."""
    src = _seed_files(workdir, files, size_kb)
    return ["sh", "-c",
            f'for f in "{src}"/*.dat; do gpg --batch --yes --passphrase x -c "$f"; done']


def _openssl_enc(workdir, files, size_kb):
    """정상 파일 암호화 (openssl). 랜섬웨어와 표면적으로 가장 닮은 정상 작업."""
    src = _seed_files(workdir, files, size_kb)
    return ["sh", "-c",
            f'for f in "{src}"/*.dat; do openssl enc -aes-256-cbc -pbkdf2 '
            f'-pass pass:x -in "$f" -out "$f.enc"; done']


def _shred_delete(workdir, files, size_kb):
    """보안 삭제 — 덮어쓰기 후 삭제. 랜섬웨어의 원본 파괴와 표면적으로 유사한 정상 작업."""
    src = _seed_files(workdir, files, size_kb)
    return ["sh", "-c", f'shred -u -n 1 "{src}"/*.dat']


def _cp_archive(workdir, files, size_kb):
    src = _seed_files(workdir, files, size_kb)
    return ["cp", "-a", src, os.path.join(workdir, "archive")]


def _rsync_mirror(workdir, files, size_kb):
    src = _seed_files(workdir, files, size_kb) + "/"
    return ["rsync", "-a", src, os.path.join(workdir, "mirror") + "/"]


def _sha256_all(workdir, files, size_kb):
    src = _seed_files(workdir, files, size_kb)
    return ["sh", "-c", f'find "{src}" -type f -exec sha256sum {{}} + > "{workdir}/hashes.txt"']


def _grep_recursive(workdir, files, size_kb):
    src = _seed_tree(workdir, files, size_kb)
    return ["sh", "-c", f'grep -r "fox" "{src}" > "{workdir}/matches.txt" || true']


def _find_chmod(workdir, files, size_kb):
    """대량 권한 변경 — 랜섬웨어가 종종 하는 chmod를 정상 맥락(배포 준비 등)으로."""
    src = _seed_files(workdir, files, size_kb)
    return ["sh", "-c", f'find "{src}" -type f -exec chmod 600 {{}} +']


def _sort_large(workdir, files, size_kb):
    src = _seed_files(workdir, files, size_kb)
    return ["sh", "-c",
            f'cat "{src}"/*.dat | sort > "{workdir}/sorted.txt"']


def _split_join(workdir, files, size_kb):
    """큰 파일을 조각내고 다시 합치기 — 다운로드/전송 도구의 전형적 I/O."""
    big = os.path.join(workdir, "big.bin")
    _write_random(big, max(files * size_kb, 1024))
    out = os.path.join(workdir, "parts")
    os.makedirs(out, exist_ok=True)
    return ["sh", "-c",
            f'split -b 64k "{big}" "{out}/part_" && cat "{out}"/part_* > "{workdir}/joined.bin"']


def _base64_roundtrip(workdir, files, size_kb):
    src = _seed_files(workdir, files, size_kb)
    return ["sh", "-c",
            f'for f in "{src}"/*.dat; do base64 "$f" > "$f.b64"; base64 -d "$f.b64" > "$f.dec"; done']


def _dd_copy(workdir, files, size_kb):
    big = os.path.join(workdir, "src.bin")
    _write_random(big, max(files * size_kb, 512))
    return ["dd", f"if={big}", f"of={os.path.join(workdir, 'copy.bin')}", "bs=64k"]


def _gcc_compile(workdir, files, size_kb):
    """여러 소스 컴파일 — 개발 워크플로의 대량 파일 생성/링크."""
    src = os.path.join(workdir, "src")
    os.makedirs(src, exist_ok=True)
    n = max(min(files, 50), 3)
    for i in range(n):
        with open(os.path.join(src, f"mod{i}.c"), "w") as f:
            f.write(f"int f{i}(int x){{return x*{i}+{i};}}\n")
    with open(os.path.join(src, "main.c"), "w") as f:
        f.write("int main(void){return 0;}\n")
    return ["sh", "-c",
            f'cd "{src}" && for c in mod*.c; do gcc -c "$c" -o "${{c%.c}}.o"; done && '
            f'gcc main.c mod*.o -o "{workdir}/app"']


def _pandoc_convert(workdir, files, size_kb):
    src = os.path.join(workdir, "docs")
    os.makedirs(src, exist_ok=True)
    n = max(min(files, 50), 3)
    for i in range(n):
        with open(os.path.join(src, f"doc{i}.md"), "w") as f:
            f.write(f"# Title {i}\n\n" + ("Some **markdown** text. " * 50) + "\n")
    return ["sh", "-c",
            f'for m in "{src}"/*.md; do pandoc "$m" -o "${{m%.md}}.html"; done']


def _imagemagick_convert(workdir, files, size_kb):
    src = os.path.join(workdir, "img")
    os.makedirs(src, exist_ok=True)
    n = max(min(files, 50), 3)
    gen = " ".join(
        f'convert -size 128x128 xc:gray "{src}/i{i}.png";' for i in range(n))
    return ["sh", "-c",
            f'{gen} for p in "{src}"/*.png; do convert "$p" "${{p%.png}}.jpg"; done']


def _ffmpeg_transcode(workdir, files, size_kb):
    src = os.path.join(workdir, "audio")
    os.makedirs(src, exist_ok=True)
    n = max(min(files, 20), 2)
    gen = " ".join(
        f'ffmpeg -y -f lavfi -i "sine=frequency={220 + i * 20}:duration=1" '
        f'"{src}/a{i}.wav" 2>/dev/null;' for i in range(n))
    return ["sh", "-c",
            f'{gen} for w in "{src}"/*.wav; do ffmpeg -y -i "$w" '
            f'"${{w%.wav}}.flac" 2>/dev/null; done']


# name -> (needs, command_builder)
WORKLOADS = {
    # 기존 15종
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
    # 추가: 압축
    "bzip2_each":       (["bzip2"], _bzip2_each),
    "xz_each":          (["xz"], _xz_each),
    "zstd_each":        (["zstd"], _zstd_each),
    # 추가: 정상 암호화 (고엔트로피 대조군 — 매우 중요)
    "gpg_symmetric":    (["gpg"], _gpg_symmetric),
    "openssl_enc":      (["openssl"], _openssl_enc),
    # 추가: 파일 파괴/변경 (랜섬웨어와 표면적으로 유사한 정상)
    "shred_delete":     (["shred"], _shred_delete),
    "find_chmod":       (["find", "chmod"], _find_chmod),
    # 추가: 복사/동기화
    "cp_archive":       (["cp"], _cp_archive),
    "rsync_mirror":     (["rsync"], _rsync_mirror),
    "dd_copy":          (["dd"], _dd_copy),
    "split_join":       (["split", "cat"], _split_join),
    # 추가: 대량 텍스트/해시 처리
    "sha256_all":       (["find", "sha256sum"], _sha256_all),
    "grep_recursive":   (["grep"], _grep_recursive),
    "sort_large":       (["sort"], _sort_large),
    "base64_roundtrip": (["base64"], _base64_roundtrip),
    # 추가: 개발/문서/미디어 변환
    "gcc_compile":      (["gcc"], _gcc_compile),
    "pandoc_convert":   (["pandoc"], _pandoc_convert),
    "imagemagick":      (["convert"], _imagemagick_convert),
    "ffmpeg_transcode": (["ffmpeg"], _ffmpeg_transcode),
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
