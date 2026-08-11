#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct data_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    char type[8];        // "O", "C", "W", "D", "E" 딱 한 글자용
    char filename[256];
};

BPF_PERF_OUTPUT(events);
BPF_HASH(ignore_pid, u32, u32);

// 공통 제출 함수
static inline void submit_manual(void *ctx, char *type_str, const char __user *filename) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (ignore_pid.lookup(&pid)) return;

    struct data_t data = {};
    data.pid = pid;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    // 타입 복사 (O, C, W, D, E)
    __builtin_memcpy(data.type, type_str, 2);
    
    // 파일 경로 읽기
    if (filename != NULL) {
        bpf_probe_read_user_str(&data.filename, sizeof(data.filename), filename);
    } else {
        __builtin_memcpy(data.filename, "N/A", 4);
    }

    events.perf_submit(ctx, &data, sizeof(data));
}

// 1 & 2. OPEN / CREATE 구분
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    if (args->flags & 64) { // O_CREAT
        submit_manual(args, "C", args->filename);
    } else {
        submit_manual(args, "O", args->filename);
    }
    return 0;
}

// [수정] 3. WRITE - 일반 write와 pwrite64를 모두 잡습니다.
TRACEPOINT_PROBE(syscalls, sys_enter_write) {
    submit_manual(args, "W", NULL);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_pwrite64) {
    submit_manual(args, "W", NULL);
    return 0;
}

// [추가] 3-2. MMAP - 메모리 맵핑을 통한 수정 시도 탐지
TRACEPOINT_PROBE(syscalls, sys_enter_mmap) {
    // mmap 시 flags에 PROT_WRITE(2)가 포함된 경우만 'W'로 간주
    if (args->prot & 2) {
        submit_manual(args, "W", NULL);
    }
    return 0;
}


// 4. DELETE (핵심!)
TRACEPOINT_PROBE(syscalls, sys_enter_unlinkat) {
    submit_manual(args, "D", args->pathname); // unlinkat은 pathname 사용
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_unlink) {
    submit_manual(args, "D", args->pathname); // 구버전 대응
    return 0;
}

// 5. ENCRYPT (Uprobe용)
int detect_encrypt(struct pt_regs *ctx) {
    submit_manual(ctx, "E", (const char __user *)"OPENSSL_CRYPTO");
    return 0;
}