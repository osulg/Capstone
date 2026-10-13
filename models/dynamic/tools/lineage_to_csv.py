import argparse
import json
from pathlib import Path
from collections import defaultdict, deque

import pandas as pd


GRAMS = [
    'CCC','CCD','CCO','CDC','CDD','CDO','COC','COD','COO',
    'DCC','DCD','DCO','DDC','DDD','DDO','DOC','DOD','DOO',
    'EEE','EEO','EOE','EOO','OCC','OCD','OCO','ODC','ODD',
    'ODO','OEE','OOC','OOD','OOO'
]

TRAIN_COLUMNS = [
    'PID',
    'O_sum',
    'C_sum',
    'D_sum',
    'E_sum',
    'Is_System_Path',
    'Is_Test_Path',
    'is_dev',
    *GRAMS,
    'Label',
    'Type'
]


def load_jsonl(path):
    records = []

    with open(path, "r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()

            if not line:
                continue

            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as e:
                print(
                    f"[WARN] JSON 오류: "
                    f"line={lineno}: {e}"
                )

    return records


def split_process_instances(records):
    """
    동일 TGID가 나중에 재사용되더라도 서로 다른 프로세스로 취급한다.

    기본 생명주기:
        F -> X -> file events -> Z

    F를 놓쳤거나 collector 시작 전에 존재하던 프로세스는
    첫 관측 이벤트부터 implicit instance로 만든다.
    """

    ordered = sorted(
        records,
        key=lambda x: int(x.get("ts_ns", 0))
    )

    active = {}
    instance_seq = defaultdict(int)
    completed = []

    for record in ordered:
        tgid = int(record["tgid"])
        action = str(
            record.get("action", "")
        ).upper()

        # 새 프로세스 생성.
        # 같은 TGID의 이전 instance가 아직 남아 있으면
        # Z 유실 등으로 판단하고 이전 것을 incomplete로 종료한다.
        if action == "F":

            if tgid in active:
                stale = active.pop(tgid)
                stale["closed"] = False
                completed.append(stale)

            instance_seq[tgid] += 1

            active[tgid] = {
                "tgid": tgid,
                "instance_no": instance_seq[tgid],
                "started_by": "F",
                "closed": False,
                "events": [record]
            }

            continue

        # F 이벤트 없이 처음 관측된 프로세스
        if tgid not in active:

            instance_seq[tgid] += 1

            active[tgid] = {
                "tgid": tgid,
                "instance_no": instance_seq[tgid],
                "started_by": "implicit",
                "closed": False,
                "events": []
            }

        active[tgid]["events"].append(
            record
        )

        # process leader의 Z만 bpf.py가 저장하므로
        # 여기서는 Z를 해당 process instance의 끝으로 사용한다.
        if action == "Z":

            finished = active.pop(tgid)
            finished["closed"] = True
            completed.append(finished)

    # collector가 먼저 종료되어 Z를 못 본 process
    for instance in active.values():
        instance["closed"] = False
        completed.append(instance)

    completed.sort(
        key=lambda inst: int(
            inst["events"][0].get(
                "ts_ns",
                0
            )
        )
    )

    return completed


def build_features(records, type_id):

    instances = split_process_instances(
        records
    )

    rows = []
    audit_rows = []

    skipped_unknown = 0
    skipped_conflict = 0
    skipped_no_behavior = 0

    for instance in instances:

        tgid = instance["tgid"]
        instance_no = instance["instance_no"]

        events = instance["events"]

        exec_events = [
            e for e in events
            if e.get("action") == "X"
        ]

        behavior = [
            e for e in events
            if e.get("action")
            in {"O", "C", "D", "E"}
        ]

        if not behavior:
            skipped_no_behavior += 1
            continue

        labels = {
            int(
                e.get(
                    "lineage_label",
                    -1
                )
            )
            for e in behavior
        }

        # 같은 process instance에서 학습 대상 행동의
        # label이 섞이면 자동 확정하지 않고 제외한다.
        if len(labels) != 1:
            skipped_conflict += 1
            continue

        label = next(iter(labels))

        # 공격 실험 중 lineage가 확인되지 않은 PID
        # (Label=-1)는 학습 데이터에서 제외한다.
        if label == -1:
            skipped_unknown += 1
            continue

        actions = [
            e["action"]
            for e in behavior
        ]

        paths = [
            str(e.get("file", ""))
            for e in behavior
            if e.get("file")
            not in (None, "", "N/A")
        ]

        row = {
            "PID": tgid,
            "O_sum": actions.count("O"),
            "C_sum": actions.count("C"),
            "D_sum": actions.count("D"),
            "E_sum": actions.count("E"),

            "Is_System_Path": int(
                any(
                    any(
                        token in path
                        for token in (
                            "/dev/",
                            "/run/",
                            "/etc/",
                            "/sys/"
                        )
                    )
                    for path in paths
                )
            ),

            "Is_Test_Path": int(
                any(
                    "/test_files/" in path
                    for path in paths
                )
            ),

            "is_dev": int(
                any(
                    "/dev/" in path
                    for path in paths
                )
            ),

            **{
                gram: 0
                for gram in GRAMS
            },

            "Label": label,
            "Type": type_id
        }

        history = deque(maxlen=3)

        for action in actions:
            history.append(action)

            if len(history) == 3:
                gram = "".join(history)

                if gram in row:
                    row[gram] += 1

        rows.append(row)

        exe_chain = []

        for event in exec_events:

            exe = str(
                event.get(
                    "exe",
                    ""
                )
            )

            if (
                exe
                and (
                    not exe_chain
                    or exe_chain[-1] != exe
                )
            ):
                exe_chain.append(exe)

        first = events[0]
        latest = events[-1]

        audit_rows.append({
            "Type": type_id,
            "PID": tgid,
            "Instance_No": instance_no,
            "Instance_ID": (
                f"{tgid}:{instance_no}"
            ),
            "Started_By": instance[
                "started_by"
            ],
            "Exit_Seen": int(
                instance["closed"]
            ),
            "PPID": latest.get("ppid"),
            "Root_TGID": latest.get(
                "root_tgid"
            ),
            "Relation": latest.get(
                "relation"
            ),
            "Label": label,
            "Event_Count": len(
                behavior
            ),
            "Exec_Chain": " -> ".join(
                exe_chain
            ),
            "Start_ns": first.get(
                "ts_ns"
            ),
            "End_ns": latest.get(
                "ts_ns"
            )
        })

    df = pd.DataFrame(
        rows,
        columns=TRAIN_COLUMNS
    )

    audit = pd.DataFrame(
        audit_rows
    )

    return (
        df,
        audit,
        skipped_unknown,
        skipped_conflict,
        skipped_no_behavior
    )


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--input",
        required=True
    )

    parser.add_argument(
        "--type",
        required=True,
        help="실험/샘플 식별자"
    )

    parser.add_argument(
        "--output",
        required=True
    )

    args = parser.parse_args()

    records = load_jsonl(args.input)

    (
        df,
        audit,
        unknown,
        conflict,
        no_behavior
    ) = build_features(
        records,
        args.type
    )

    output = Path(args.output)

    df.to_csv(
        output,
        index=False
    )

    audit_path = output.with_name(
        output.stem + "_audit.csv"
    )

    audit.to_csv(
        audit_path,
        index=False
    )

    print("=" * 60)
    print("Lineage JSONL -> ML CSV")
    print("=" * 60)

    print("원본 JSON 이벤트:", len(records))
    print("생성된 학습 행:", len(df))

    if len(df):
        print(
            "정상:",
            int((df["Label"] == 0).sum())
        )

        print(
            "악성:",
            int((df["Label"] == 1).sum())
        )

    print("Unknown 제외:", unknown)
    print("Label conflict 제외:", conflict)
    print("행동 없는 PID 제외:", no_behavior)

    print()
    print("학습 CSV:", output)
    print("Audit CSV:", audit_path)

    if len(df):
        print("\n[생성 결과]")
        print(df.to_string(index=False))


if __name__ == "__main__":
    main()
