# GuardFS demo scenarios

## S01: normal file operations

Run on Linux from the repository root after starting GuardFS:

```bash
python3 -m scenarios.s01_normal
```

If multiple GuardFS processes exist, specify the process serving this mount:

```bash
python3 -m scenarios.s01_normal --guardfs-pid <PID> \
  --mount "$HOME/guardfs_runtime/mount" \
  --underlay "$HOME/guardfs_runtime/underlay"
```

The scenario runs CREATE, WRITE, READ, MKDIR, RENAME, READ_AFTER_RENAME,
UNLINK and RMDIR in a unique `s01_<uuid>` directory. Writes and deletions
use only the mount. Every step checks underlay propagation and mount/process
health. A successful run removes its own directory; a failed run stops and
retains artifacts for inspection (no recursive cleanup).

Progress goes to stderr. The final JSON report goes to stdout:

```bash
python3 -m scenarios.s01_normal > /tmp/s01-result.json
```

Exit code: 0 for verified file operations, 1 for failure. The report includes
the test PID, GuardFS PID, run ID, per-step results and content SHA-256.
`passed` refers to file operations only: LOW state and absence of false
positives are **not yet verified** (`detection_verification: not_checked`).
No state overrides or detection thresholds are changed. The supplied underlay
must correspond to the mounted GuardFS instance; specify the correct PID when
auto-discovery is ambiguous. The caller should impose a process timeout when
integrating with the web runner, since an unresponsive FUSE call can block.
