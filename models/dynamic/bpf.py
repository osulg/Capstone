from bcc import BPF
import os, socket, ctypes, sys

# 1. 환경 설정
UDP_IP = "192.168.1.1"   # Sandbox Host VM IP
UDP_PORT = 9999
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# 감시할 경로
TARGET_DIR = "/home/capstone/"

print("[*] eBPF 모듈 컴파일 및 라이브러리/프로브 로드 중...")

lib_path = "/lib/x86_64-linux-gnu/libcrypto.so.3"

try:
    # 2. bpf.c 로드
    b = BPF(src_file="bpf.c")

    # 3. uprobes 등록 (OpenSSL 암호화 함수)
    crypto_functions = ["EVP_EncryptInit_ex", "EVP_CipherInit_ex", "EVP_SealInit_ex"]
    for func in crypto_functions:
        try:
            b.attach_uprobe(name=lib_path, sym=func, fn_name="detect_encrypt")
            print(f"[*] uprobe 등록 성공: {func}")
        except Exception as e:
            print(f"[!] {func} 등록 실패: {e}")

    # 4. 자기 자신 PID 제외
    my_pid = os.getpid()
    b["ignore_pid"][ctypes.c_uint32(my_pid)] = ctypes.c_uint32(1)

    print(f"[*] 탐지기 로드 성공! (내 PID: {my_pid})")
    print(f"[*] 감시 경로: {TARGET_DIR}")

except Exception as e:
    print(f"[!] 초기화 중 치명적 에러 발생: {e}")
    sys.exit(1)

# 5. 이벤트 콜백
def print_event(cpu, data, size):
    event = b["events"].event(data)
    comm = event.comm.decode(errors="replace")
    filename = event.filename.decode(errors="replace")
    
    # action을 깨끗하게 정리 (대소문자 구분 없이 처리)
    action = event.type.decode(errors="replace").strip().strip('\x00').upper()

    # [디버깅용] 모든 액션을 일단 다 보고 싶다면 아래 주석 해제
    # print(f"DEBUG: PID={event.pid}, Comm={comm}, Action={action}, File={filename}")

    # 필터 조건: D(Delete)가 포함되어 있거나 감시 경로 내 파일인 경우
    if action == "D" or action == "DELETE" or (TARGET_DIR in filename):
        log_msg = f"[{event.pid}] {comm} {action} {filename}"
        print(f"[ALERT] {log_msg}", flush=True)
        try:
            sock.sendto(log_msg.encode(), (UDP_IP, UDP_PORT))
        except Exception:
            pass

# 6. 폴링 루프
b["events"].open_perf_buffer(print_event)
print("--- [실시간 통합 탐지 시작 (O, C, D, E 감시 중)] ---", flush=True)

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("\n[*] 중단됨. 수집된 데이터를 확인하세요.")
        sys.exit(0)