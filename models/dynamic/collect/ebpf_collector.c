/*
 * GuardFS 동적 데이터 수집용 eBPF 프로그램 (BCC, x86_64 전용)
 *
 * - tracked 맵에 등록된 TGID와 그 자손 프로세스만 수집한다.
 *   (수집기가 실행한 워크로드 트리 = 실행 1회 = 샘플 1개)
 * - 파일 연산은 raw_syscalls enter에서 인자를 보관하고, exit에서
 *   성공(ret >= 0)한 경우에만 이벤트를 낸다. FUSE 로그와 같은 기준이다.
 * - ring buffer를 사용해 CPU 간 이벤트 순서가 뒤섞이지 않게 한다. (커널 5.8+)
 * - task_struct 등 커널 내부 구조체를 읽지 않는다. 헤더 버전이 실행 커널과
 *   달라도 필드 오프셋 차이로 값이 틀어지지 않게 하기 위해서다.
 *   ppid는 사용자 공간에서 FORK 이벤트로 추적한다.
 * - OP_* 값은 ebpf_events.py의 OPS에서 cflags로 주입된다.
 */

#include <uapi/linux/ptrace.h>

#define COMM_LEN 16
#define PATH_LEN 256
#define AT_FDCWD_ -100
#define O_CREAT_ 0100
#define O_DIRECTORY_ 0200000
#define AT_REMOVEDIR_ 0x200
#define F_DUPFD_ 0
#define F_DUPFD_CLOEXEC_ 1030

/* x86_64 syscall 번호 */
#define NR_read 0
#define NR_write 1
#define NR_open 2
#define NR_close 3
#define NR_pread64 17
#define NR_pwrite64 18
#define NR_readv 19
#define NR_writev 20
#define NR_dup 32
#define NR_dup2 33
#define NR_sendfile 40
#define NR_fcntl 72
#define NR_truncate 76
#define NR_ftruncate 77
#define NR_chdir 80
#define NR_fchdir 81
#define NR_rename 82
#define NR_mkdir 83
#define NR_rmdir 84
#define NR_creat 85
#define NR_unlink 87
#define NR_chmod 90
#define NR_fchmod 91
#define NR_openat 257
#define NR_mkdirat 258
#define NR_unlinkat 263
#define NR_renameat 264
#define NR_fchmodat 268
#define NR_dup3 292
#define NR_preadv 295
#define NR_pwritev 296
#define NR_renameat2 316
#define NR_copy_file_range 326
#define NR_preadv2 327
#define NR_pwritev2 328
#define NR_openat2 437
#define NR_fchmodat2 452

struct event_t {
    u64 ts_ns;
    s64 ret;
    s64 size;
    s64 offset;
    u32 tgid;
    u32 tid;
    u32 op;
    s32 fd;
    s32 fd2;
    u32 flags;
    char comm[COMM_LEN];
    char path[PATH_LEN];
    char path2[PATH_LEN];
};

BPF_RINGBUF_OUTPUT(events, 1 << 10);

BPF_HASH(tracked, u32, u8, 65536);
BPF_TABLE("lru_hash", u64, struct event_t, pending, 16384);
BPF_PERCPU_ARRAY(scratch, struct event_t, 1);
BPF_ARRAY(drops, u64, 1);

static inline void fill_header(struct event_t *e, u32 op)
{
    u64 id = bpf_get_current_pid_tgid();

    e->ts_ns = bpf_ktime_get_ns();
    e->ret = 0;
    e->size = -1;
    e->offset = -1;
    e->tgid = id >> 32;
    e->tid = (u32)id;
    e->op = op;
    e->fd = -1;
    e->fd2 = AT_FDCWD_;
    e->flags = 0;
    e->path[0] = 0;
    e->path2[0] = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

static inline struct event_t *reserve(void)
{
    struct event_t *e = events.ringbuf_reserve(sizeof(struct event_t));

    if (!e) {
        u32 zero = 0;
        drops.increment(zero);
    }
    return e;
}

static inline int is_tracked(u32 tgid)
{
    return tracked.lookup(&tgid) != NULL;
}

TRACEPOINT_PROBE(raw_syscalls, sys_enter)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;

    if (!is_tracked(tgid))
        return 0;

    long nr = args->id;
    u32 zero = 0;
    struct event_t *p = scratch.lookup(&zero);

    if (!p)
        return 0;

    fill_header(p, 0);

    const char *u1 = NULL;
    const char *u2 = NULL;

    switch (nr) {
    case NR_read:
    case NR_readv:
    case NR_preadv2:
        p->op = OP_READ;
        p->fd = args->args[0];
        break;
    case NR_pread64:
    case NR_preadv:
        p->op = OP_READ;
        p->fd = args->args[0];
        p->offset = args->args[3];
        break;
    case NR_write:
    case NR_writev:
    case NR_pwritev2:
        p->op = OP_WRITE;
        p->fd = args->args[0];
        break;
    case NR_pwrite64:
    case NR_pwritev:
        p->op = OP_WRITE;
        p->fd = args->args[0];
        p->offset = args->args[3];
        break;
    case NR_sendfile:
        p->op = OP_COPY;
        p->fd = args->args[0];
        p->fd2 = args->args[1];
        break;
    case NR_copy_file_range:
        p->op = OP_COPY;
        p->fd = args->args[2];
        p->fd2 = args->args[0];
        break;
    case NR_open:
        u1 = (const char *)args->args[0];
        p->flags = args->args[1];
        break;
    case NR_creat:
        u1 = (const char *)args->args[0];
        p->flags = O_CREAT_;
        break;
    case NR_openat:
        p->fd2 = args->args[0];
        u1 = (const char *)args->args[1];
        p->flags = args->args[2];
        break;
    case NR_openat2: {
        u64 how_flags = 0;
        p->fd2 = args->args[0];
        u1 = (const char *)args->args[1];
        bpf_probe_read_user(&how_flags, sizeof(how_flags), (void *)args->args[2]);
        p->flags = how_flags;
        break;
    }
    case NR_close:
        p->op = OP_CLOSE;
        p->fd = args->args[0];
        break;
    case NR_dup:
    case NR_dup2:
        p->op = OP_DUP;
        p->fd2 = args->args[0];
        break;
    case NR_dup3:
        p->op = OP_DUP;
        p->fd2 = args->args[0];
        p->flags = args->args[2];
        break;
    case NR_fcntl:
        if (args->args[1] != F_DUPFD_ && args->args[1] != F_DUPFD_CLOEXEC_)
            return 0;
        p->op = OP_DUP;
        p->fd2 = args->args[0];
        p->flags = args->args[1];
        break;
    case NR_chdir:
        p->op = OP_CHDIR;
        u1 = (const char *)args->args[0];
        break;
    case NR_fchdir:
        p->op = OP_CHDIR;
        p->fd = args->args[0];
        break;
    case NR_truncate:
        p->op = OP_TRUNCATE;
        u1 = (const char *)args->args[0];
        p->size = args->args[1];
        break;
    case NR_ftruncate:
        p->op = OP_TRUNCATE;
        p->fd = args->args[0];
        p->size = args->args[1];
        break;
    case NR_rename:
        p->op = OP_RENAME;
        p->fd = AT_FDCWD_;
        u1 = (const char *)args->args[0];
        u2 = (const char *)args->args[1];
        break;
    case NR_renameat:
    case NR_renameat2:
        p->op = OP_RENAME;
        p->fd2 = args->args[0];
        u1 = (const char *)args->args[1];
        p->fd = args->args[2];
        u2 = (const char *)args->args[3];
        break;
    case NR_mkdir:
        p->op = OP_MKDIR;
        u1 = (const char *)args->args[0];
        break;
    case NR_mkdirat:
        p->op = OP_MKDIR;
        p->fd2 = args->args[0];
        u1 = (const char *)args->args[1];
        break;
    case NR_rmdir:
        p->op = OP_RMDIR;
        u1 = (const char *)args->args[0];
        break;
    case NR_unlink:
        p->op = OP_UNLINK;
        u1 = (const char *)args->args[0];
        break;
    case NR_unlinkat:
        p->op = (args->args[2] & AT_REMOVEDIR_) ? OP_RMDIR : OP_UNLINK;
        p->fd2 = args->args[0];
        u1 = (const char *)args->args[1];
        break;
    case NR_chmod:
        p->op = OP_CHMOD;
        u1 = (const char *)args->args[0];
        break;
    case NR_fchmod:
        p->op = OP_CHMOD;
        p->fd = args->args[0];
        break;
    case NR_fchmodat:
    case NR_fchmodat2:
        p->op = OP_CHMOD;
        p->fd2 = args->args[0];
        u1 = (const char *)args->args[1];
        break;
    default:
        return 0;
    }

    /* open 계열: 플래그로 OPEN / CREATE / OPENDIR 구분 */
    if (p->op == 0) {
        if (p->flags & O_CREAT_)
            p->op = OP_CREATE;
        else if (p->flags & O_DIRECTORY_)
            p->op = OP_OPENDIR;
        else
            p->op = OP_OPEN;
    }

    if (u1)
        bpf_probe_read_user_str(&p->path, sizeof(p->path), u1);
    if (u2)
        bpf_probe_read_user_str(&p->path2, sizeof(p->path2), u2);

    pending.update(&id, p);
    return 0;
}

TRACEPOINT_PROBE(raw_syscalls, sys_exit)
{
    u64 id = bpf_get_current_pid_tgid();
    struct event_t *p = pending.lookup(&id);

    if (!p)
        return 0;

    if (args->ret >= 0) {
        struct event_t *e = reserve();

        if (e) {
            bpf_probe_read_kernel(e, sizeof(*e), p);
            e->ts_ns = bpf_ktime_get_ns();
            e->ret = args->ret;
            events.ringbuf_submit(e, 0);
        }
    }

    pending.delete(&id);
    return 0;
}

/*
 * fork/clone. 이 시점의 current는 부모다.
 * tracepoint 인자만으로는 새 스레드와 새 프로세스를 구분할 수 없어서
 * child_pid를 일단 등록한다. 스레드였다면 그 키는 TGID 조회에 쓰이지 않고
 * 스레드 종료 시 제거된다. 구분은 사용자 공간에서 한다.
 */
TRACEPOINT_PROBE(sched, sched_process_fork)
{
    u32 parent_tgid = bpf_get_current_pid_tgid() >> 32;
    u32 child_pid = args->child_pid;

    if (!is_tracked(parent_tgid))
        return 0;

    u8 one = 1;
    tracked.update(&child_pid, &one);

    struct event_t *e = reserve();
    if (!e)
        return 0;

    fill_header(e, OP_FORK);
    e->fd = child_pid;
    events.ringbuf_submit(e, 0);
    return 0;
}

TRACEPOINT_PROBE(sched, sched_process_exec)
{
    u32 tgid = bpf_get_current_pid_tgid() >> 32;

    if (!is_tracked(tgid))
        return 0;

    struct event_t *e = reserve();
    if (!e)
        return 0;

    fill_header(e, OP_EXEC);

    u32 filename_off = args->data_loc_filename & 0xFFFF;
    bpf_probe_read_kernel_str(&e->path, sizeof(e->path), (const char *)args + filename_off);

    events.ringbuf_submit(e, 0);
    return 0;
}

/*
 * 스레드/프로세스 종료. 종료하는 TID 키를 제거한다.
 * 리더(TID == TGID)면 프로세스 추적이 끝나고, 스레드면 fork 때 등록된 키만 지워진다.
 */
TRACEPOINT_PROBE(sched, sched_process_exit)
{
    u32 tid = (u32)bpf_get_current_pid_tgid();

    if (!is_tracked(tid))
        return 0;

    tracked.delete(&tid);

    struct event_t *e = reserve();
    if (!e)
        return 0;

    fill_header(e, OP_EXIT);
    events.ringbuf_submit(e, 0);
    return 0;
}

/* OpenSSL 암호화 초기화 호출 (동적 링크된 libcrypto에서만 관측 가능) */
int on_crypto(struct pt_regs *ctx)
{
    u32 tgid = bpf_get_current_pid_tgid() >> 32;

    if (!is_tracked(tgid))
        return 0;

    struct event_t *e = reserve();
    if (!e)
        return 0;

    fill_header(e, OP_CRYPTO);
    events.ringbuf_submit(e, 0);
    return 0;
}
