#!/usr/bin/env python3
"""
GuardFS 진입점
사용:
    python3 -m guardfs.main [<MOUNT_DIR> <UNDERLAY_DIR>]
인자를 생략하면 common/paths.py의 기본 runtime 경로를 사용한다.
"""
import os
import sys

from guardfs.common import paths
from guardfs.fuse_fs.passthrough import run_fuse


def main():
    if len(sys.argv) == 3:
        mount_dir, underlay_dir = sys.argv[1], sys.argv[2]
    elif len(sys.argv) == 1:
        mount_dir = str(paths.MOUNT_DIR)
        underlay_dir = str(paths.UNDERLAY_DIR)
    else:
        print("Usage: python3 -m guardfs.main [<MOUNT_DIR> <UNDERLAY_DIR>]")
        sys.exit(2)

    for d in (mount_dir, underlay_dir,
              os.path.join(underlay_dir, "honeypot")):
        os.makedirs(d, exist_ok=True)
    os.makedirs(paths.RUNTIME_DIR, exist_ok=True)

    print(f"[GUARDFS] mount={mount_dir} underlay={underlay_dir}")
    run_fuse(mount_dir, underlay_dir)


if __name__ == "__main__":
    main()
