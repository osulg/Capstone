#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct exec_info_t {
    char filename[256];
};

struct data_t {
    u64 ts_ns;

    u32 tgid;
    u32 tid;
    u32 ppid;

    char comm[TASK_COMM_LEN];
    char type[8];
    char filename[256];
};

BPF_PERF_OUTPUT(events);
BPF_HASH(ignore_pid, u32, u32);

/*
 * userspace(bpf.py)에서 등록한 UID만 수집한다.
 * 등록 전에는 어떤 UID의 이벤트도 통과시키지 않는다.
 */
BPF_HASH(target_uid, u32, u32);

static inline int is_target_uid(void)
{
    u32 uid = (u32)bpf_get_current_uid_gid();
    u32 *enabled = target_uid.lookup(&uid);

    return enabled != NULL;
}

/*
 * execve 진입 시 실행 예정 파일을 잠시 보관.
 * 성공한 exec만 X 이벤트로 전달한다.
 */
BPF_HASH(pending_exec, u32, struct exec_info_t);

/*
 * eBPF stack은 512 byte로 작기 때문에
 * 큰 data_t를 stack에 만들지 않고 per-CPU 임시 버퍼를 사용한다.
 */
BPF_PERCPU_ARRAY(exec_event_scratch, struct data_t, 1);


/* 현재 프로세스의 부모 TGID */
static inline u32 get_current_ppid(void)
{
    struct task_struct *task;
    struct task_struct *parent = NULL;
    u32 ppid = 0;

    task = (struct task_struct *)bpf_get_current_task();

    bpf_probe_read_kernel(
        &parent,
        sizeof(parent),
        &task->real_parent
    );

    if (parent) {
        bpf_probe_read_kernel(
            &ppid,
            sizeof(ppid),
            &parent->tgid
        );
    }

    return ppid;
}


/* 공통 파일 이벤트 제출 */
static inline void submit_manual(
    void *ctx,
    char *type_str,
    const char __user *filename
)
{
    u64 id = bpf_get_current_pid_tgid();

    u32 tgid = id >> 32;
    u32 tid = (u32)id;

    if (!is_target_uid())
        return;

    if (ignore_pid.lookup(&tgid))
        return;

    struct data_t data = {};

    data.ts_ns = bpf_ktime_get_ns();

    data.tgid = tgid;
    data.tid = tid;
    data.ppid = get_current_ppid();

    bpf_get_current_comm(
        &data.comm,
        sizeof(data.comm)
    );

    __builtin_memcpy(
        data.type,
        type_str,
        2
    );

    if (filename != NULL) {
        bpf_probe_read_user_str(
            &data.filename,
            sizeof(data.filename),
            filename
        );
    } else {
        __builtin_memcpy(
            data.filename,
            "N/A",
            4
        );
    }

    events.perf_submit(
        ctx,
        &data,
        sizeof(data)
    );
}


/*
 * EXEC 진입:
 * 실행하려는 파일명을 임시 캐시에 저장.
 */
TRACEPOINT_PROBE(syscalls, sys_enter_execve)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;

    if (!is_target_uid())
        return 0;

    if (ignore_pid.lookup(&tgid))
        return 0;

    struct exec_info_t info = {};

    bpf_probe_read_user_str(
        &info.filename,
        sizeof(info.filename),
        args->filename
    );

    pending_exec.update(
        &tgid,
        &info
    );

    return 0;
}


/*
 * EXEC 종료:
 * 성공한 execve만 X 이벤트로 보낸다.
 *
 * Python 쪽에서:
 * TGID -> PPID -> executable
 * 캐시를 만들 때 사용한다.
 */
TRACEPOINT_PROBE(syscalls, sys_exit_execve)
{
    u64 id = bpf_get_current_pid_tgid();

    u32 tgid = id >> 32;
    u32 tid = (u32)id;

    struct exec_info_t *info;

    info = pending_exec.lookup(&tgid);

    if (!info)
        return 0;

    /*
     * execve 실패
     */
    if (args->ret < 0) {
        pending_exec.delete(&tgid);
        return 0;
    }

    if (ignore_pid.lookup(&tgid)) {
        pending_exec.delete(&tgid);
        return 0;
    }

    /*
     * data_t를 stack에 만들지 않고
     * per-CPU scratch map에서 가져온다.
     */
    u32 zero = 0;

    struct data_t *data =
        exec_event_scratch.lookup(&zero);

    if (!data) {
        pending_exec.delete(&tgid);
        return 0;
    }

    __builtin_memset(
        data,
        0,
        sizeof(*data)
    );

    data->ts_ns = bpf_ktime_get_ns();

    data->tgid = tgid;
    data->tid = tid;
    data->ppid = get_current_ppid();

    bpf_get_current_comm(
        &data->comm,
        sizeof(data->comm)
    );

    __builtin_memcpy(
        data->type,
        "X",
        2
    );

    __builtin_memcpy(
        data->filename,
        info->filename,
        sizeof(data->filename)
    );

    events.perf_submit(
        args,
        data,
        sizeof(*data)
    );

    pending_exec.delete(&tgid);

    return 0;
}


/* OPEN / CREATE */
TRACEPOINT_PROBE(syscalls, sys_enter_openat)
{
    if (args->flags & 64) {
        submit_manual(
            args,
            "C",
            args->filename
        );
    } else {
        submit_manual(
            args,
            "O",
            args->filename
        );
    }

    return 0;
}



/*
 * Process fork tracking
 *
 * child가 exec하기 전에 parent -> child 관계를 전달한다.
 *
 * data_t 필드 재사용:
 *   tgid = child_pid
 *   tid  = child_pid
 *   ppid = parent_pid
 *   type = "F"
 */
TRACEPOINT_PROBE(sched, sched_process_fork)
{
    if (!is_target_uid())
        return 0;

    struct data_t data = {};

    data.ts_ns = bpf_ktime_get_ns();

    data.tgid = args->child_pid;
    data.tid  = args->child_pid;
    data.ppid = args->parent_pid;

    __builtin_memcpy(
        &data.comm,
        args->child_comm,
        sizeof(data.comm)
    );

    data.type[0] = 'F';
    data.type[1] = '\0';

    events.perf_submit(
        args,
        &data,
        sizeof(data)
    );

    return 0;
}



/*
 * Process exit tracking
 *
 * sched_process_exit는 thread 단위로 발생할 수 있으므로
 * userspace에서 tid == tgid인 경우에만 process cache를 제거한다.
 *
 * type = "Z"
 */
TRACEPOINT_PROBE(sched, sched_process_exit)
{
    if (!is_target_uid())
        return 0;

    u64 id = bpf_get_current_pid_tgid();

    struct data_t data = {};

    data.ts_ns = bpf_ktime_get_ns();

    data.tgid = id >> 32;
    data.tid  = (u32)id;
    data.ppid = get_current_ppid();

    bpf_get_current_comm(
        &data.comm,
        sizeof(data.comm)
    );

    data.type[0] = 'Z';
    data.type[1] = '\0';

    events.perf_submit(
        args,
        &data,
        sizeof(data)
    );

    return 0;
}


/*
 * WRITE 수집은 현재 비활성화.
 *
 * write/pwrite/mmap 이벤트에서는 fd만 제공되고 현재 구현은
 * fd -> 실제 파일 경로를 복원하지 못해 filename이 N/A가 된다.
 * 기존 동적 ML feature도 O/C/D/E 기반이므로 불필요한 perf
 * buffer 부하를 줄이기 위해 fd-path 추적 구현 전까지 제외한다.
 */


/* DELETE */
TRACEPOINT_PROBE(syscalls, sys_enter_unlinkat)
{
    submit_manual(
        args,
        "D",
        args->pathname
    );

    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_unlink)
{
    submit_manual(
        args,
        "D",
        args->pathname
    );

    return 0;
}


/* OpenSSL encryption */
int detect_encrypt(struct pt_regs *ctx)
{
    submit_manual(
        ctx,
        "E",
        (const char __user *)"OPENSSL_CRYPTO"
    );

    return 0;
}
