# GuardFS 악성코드 동적 행위 수집 — 진행 정리 & 튜토리얼

> 이 문서는 랜섬웨어의 **파일 시스템 행위**를 FUSE + eBPF로 수집하기 위해
> 2-VM 격리 환경을 구축하고 실제 수집을 진행한 과정을 정리한 것이다.
> (Method B: Infected VM에서 악성코드 실행, Sandbox VM이 가짜 인터넷 제공)

---

## Part 1. 진행 상황 요약

### 목표
- 이미 수집된 **정상(benign)** 데이터에 더해, **악성(ransomware)** 파일시스템 행위 데이터를 수집
- 수집 데이터로 새 **동적 탐지 모델**(IsolationForest / RandomForest) 학습 준비
- 특징: FUSE(GuardFS) 관점 + eBPF 관점을 **동일 스키마**로 동시 수집, lineage 기반 라벨링

### 최종 구성 (2-VM)

| VM | IP | 역할 | 상태 |
|----|----|------|------|
| **Sandbox** (`songjiwoo`) | `192.168.85.1` | 가짜 인터넷(INetSim+dnsmasq), 백업 저장소(sshd) | 계속 켜둠, 복원 X |
| **Infected** (`infected`) | `192.168.85.3` | GuardFS(FUSE)+eBPF 수집, 악성코드 실행 | 샘플마다 스냅샷 복원 |

- **네트워크**: VMware Host-only(VMnet1), DHCP 비활성, 호스트 어댑터 분리 → **완전 격리**
- **격리 검증**: `ping 8.8.8.8` 실패 / 두 VM 간 `ping` 성공 / `nslookup` → `192.168.85.1`

### 구축한 것
- [x] VMnet1 Host-only 격리망 + 두 VM 고정 IP(netplan/networkd)
- [x] Sandbox 가짜 인터넷: **dnsmasq**(모든 도메인→85.1) + **INetSim**(HTTP 80 / HTTPS 443)
  - INetSim 자체 DNS는 최신 `Net::DNS`와 호환 문제로 죽어서 **dnsmasq로 대체**
- [x] Infected: Capstone repo + Python venv + **BCC(eBPF)** + kernel headers + GuardFS(pyfuse3/trio)
- [x] 수집 스크립트
  - `scripts/collect_one.sh` — 마운트+파일준비+eBPF수집+요약을 한 번에
  - `scripts/run_sample.sh` — 패밀리별 인자 자동화 배치 도우미
- [x] 백업 경로: Infected → `scp` → Sandbox `~/collected/`
- [x] 실제 수집: **11개 패밀리 · 약 38 run** 확보 (상세는 아래 "패밀리별 수집 결과")

### 산출물 (수집 데이터 형식)
`~/guardfs_runtime/collect/<run_id>.*`
- `<run_id>.ebpf.jsonl` — eBPF 관점 원시 이벤트
- `<run_id>.fuse.jsonl` — FUSE(GuardFS) 관점 원시 이벤트
- `.ebpf.meta.json` / `.fuse.meta.json` — run 메타데이터

`run_id` 규칙: `<family>_<sha256앞8자리>_<run번호>` (예: `avoslocker_0cd7b6ea_001`)

### 패밀리별 수집 결과 (실측)

샘플을 격리 VM에서 직접 실행해 FUSE 마운트 안(`attack_target/`)의 행위를
수집했다. 판정 기준: **암호화 행위(WRITE 폭증 + RENAME + UNLINK)가 있고,
마운트 안에만 갇혔으며(FUSE 로그 정상), 환경이 살아남은** run만 유효 데이터로 본다.

#### ✅ 수집 성공 — 모델용 데이터 (11개 패밀리, 약 38 run)

| 패밀리 | 성공/전체 | 품질 메모 |
|--------|:---:|------|
| HelloKitty | 6/6 | 전부 감염 (최상) |
| INCRansom | 4/4 | 전부 감염 (최상, `--dir <경로>/` 필요) |
| REvil | 5/6 | 전부 감염 |
| Babuk | 7/8 | 감염 정도 다양 (일부 약함) |
| AvosLocker | 5/6 | 성공 (cdca6936은 private.pem 필요로 실패) |
| Conti | 4/10 | 2개 전부 감염·1개 file_16만 |
| RansomEXX | 2/3 | 전부 감염 |
| BrainCipher | 2/2 | file_16만 감염 (약함) |
| Buhti | 1/1 | 전부 감염 |
| MONTI | 1/1 | 전부 감염 |
| MoneyMessage | 1/1 | 부분 감염 (이벤트는 확보) |

#### ⛔ 스킵 — 이유별

| 카테고리 | 패밀리 | 원인 |
|----------|--------|------|
| 비밀값 필요 | Akira, Cactus, Hive, Qilin, blackcat, lockbit, Royal, BlackSuit, BlackBasta, BlackMatter | 키/토큰/ID로 내장 config를 복호화 → 피해자별 값이라 더미로 불가 |
| ESXi 전용 | DarkSide, DragonForce, ESXi_misc, Trigona, Play | `/vmfs/volumes`·`vim-cmd`·`vsish` 의존. 개인 PC 파일 무시 |
| broad-scan 위험 | Gunra, IceFire | 마운트 밖(홈 전체)까지 암호화 → 안전환경 재구축 후 재수집 필요 (보류) |
| 기타 조건/환경 | Chaos(cron 지속성), Erebus, Interlock(FreeBSD 바이너리), DarkRadiation, ransomware_misc | 환경·조건 불일치, C2 통신 시도 등 |

#### 🔍 관찰 (분석 포인트)

- **"file_16.log만 감염" 패턴**: Babuk·BrainCipher·Conti 일부에서 반복. 세 패밀리
  모두 **Babuk 빌더 계열**이라 동일한 확장자/크기 필터를 공유하는 것으로 추정.
  → 약한 신호이므로 모델 학습 시 포함 여부/가중치 검토 필요.
- **REvil·Conti 공통 `iji` 로그**: 두 패밀리에서 동일 출력 관측 (공유 코드 조각 가능성).
- **ESXi fallback 차이**: MoneyMessage는 `vsish` 실패해도 파일 암호화를 계속(graceful),
  Trigona는 `vim-cmd` 없으면 종료(hard-depend). 같은 ESXi 겸용이라도 갈림.
- **행위-로그 불일치**: AvosLocker d7112a1e는 `[+] Encrypting` 로그 없이 실제 감염 발생.

### 겪은 이슈 & 해결 (중요 교훈)
| 이슈 | 원인 | 해결 |
|------|------|------|
| 마운트 안 파일을 malware가 못 찾음 | root(sudo)는 사용자 FUSE 마운트 접근 불가 | **`--as-user infected`로 실행**(마운트 소유자) |
| tracefs 마운트 에러 | 일반권한으로 root 전용 경로 확인 실패 | `sudo test`로 확인, 이미 마운트면 무시 |
| 실행 안 됨(`명령이 없습니다`) | 안전 위해 `chmod -x` 해둠 | 실행 직전 `chmod +x` |
| 특정 샘플 arch 오류 | 샘플셋이 멀티아키(ARM/PPC/MIPS/SPARC/S390) | x86-64/i386만 실행, 나머지 스킵 (arch 자동 체크 추가) |
| 파일 1개만 암호화(file_16) | 테스트 파일이 52바이트로 너무 작아 크기 필터에 걸림 | 테스트 파일을 **64KB 랜덤 데이터**로 확대 |
| 매 run 대상 오염 | prep이 기존 파일 안 지움 | prep이 매번 대상 폴더 **비우고** 재생성 |
| 데이터 유실 | 스냅샷 복원 전 백업 안 함 / Sandbox 실수 복원 | **백업 먼저, 복원 나중** 철칙 |
| `Failed to get block size`로 암호화 실패 (INC Ransom) | passthrough.py에 `statfs` 미구현 → pyfuse3가 ENOSYS 반환 | **passthrough.py에 `statfs` 핸들러 추가** (underlay statvfs 전달) |
| FreeBSD 바이너리가 아무 행위 안 함 (Interlock 일부) | arch 가드가 CPU만 보고 OS ABI 무시 → FreeBSD용 x86-64 통과 | run_sample.sh에 **FreeBSD 감지 추가**(file 출력에 FreeBSD면 스킵) |
| 광범위 스캔형이 수집 로그까지 암호화 (Gunra 등) | 로그가 홈 아래(collect/)에 있어 함께 암호화됨 | eBPF 로그를 **root 전용 폴더(`/var/log/guardfs`)에 격리** 후 종료 시 회수 |
| 랜섬노트만 생기고 암호화는 안 됨 | "노트 생성 ≠ 암호화". ESXi 조건/인자 미충족 | **op 분포로 판정**: WRITE/RENAME/UNLINK 없으면 실패로 간주·폐기 |

### 알려진 한계
- **비밀값 필요 패밀리**는 실행 불가(피해자별 키/토큰/ID로 config 복호화):
  Akira / Cactus / Hive / Qilin / blackcat / lockbit / Royal / BlackSuit / BlackBasta / BlackMatter
- **ESXi 전용 패밀리**는 이 Ubuntu VM에서 안 돎(`/vmfs`·`vim-cmd` 의존):
  DarkSide / DragonForce / ESXi_misc / Trigona / Play / DarkRadiation → 스킵
- **광범위 스캔형**(Gunra / IceFire)은 마운트 밖까지 암호화 → 안전환경 재구축 후 재수집 대상(현재 보류)
- **아키텍처/OS 불일치**: non-x86-64(ARM/PPC/MIPS 등) 및 FreeBSD 바이너리는 실행 불가(에뮬레이션/해당 OS 필요)
- **약한 신호 데이터**: Babuk 빌더 계열 일부는 file_16(.log)만 감염 → 모델 학습 시 취급 주의

---

## Part 2. 동적 수집 튜토리얼 (실제 진행 방법)

### 0. 전체 그림
```
[Infected VM]                         [Sandbox VM]
 GuardFS(FUSE) + eBPF 수집    ── 격리망(VMnet1) ──   dnsmasq(모든 도메인→85.1)
 악성코드 실행                                       INetSim(가짜 HTTP/HTTPS)
      │                                              (+ 백업 저장 sshd)
      └─ 어떤 도메인 요청 → 85.1(가짜)로 유도, 진짜 인터넷은 차단
```

### 1단계: 격리망 구성 (VMware)
- **Virtual Network Editor** → VMnet1을 **Host-only**, DHCP **Disabled**, "Connect a host virtual adapter" **해제**
- 두 VM의 Network Adapter를 **Custom: VMnet1**로 지정

### 2단계: 고정 IP (각 VM, netplan)
`/etc/netplan/01-netcfg.yaml` (renderer: networkd), 충돌하는 NetworkManager/cloud-init netplan은 `.bak`으로 치우고 cloud-init 네트워크 관리 비활성화.

Sandbox:
```yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    ens33:
      dhcp4: no
      addresses: [192.168.85.1/24]
```
Infected:
```yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    ens33:
      dhcp4: no
      addresses: [192.168.85.3/24]
      routes:
        - to: default
          via: 192.168.85.1
      nameservers:
        addresses: [192.168.85.1]
```
검증:
```bash
# Infected
ping -c2 192.168.85.1   # 성공
ping -c2 8.8.8.8        # 실패(격리)
```

### 3단계: 가짜 인터넷 (Sandbox)
```bash
# dnsmasq: 모든 도메인 → 192.168.85.1
sudo tee /etc/dnsmasq.d/inetsim.conf > /dev/null <<'EOF'
interface=ens33
listen-address=192.168.85.1
bind-interfaces
no-resolv
address=/#/192.168.85.1
EOF
sudo systemctl restart dnsmasq

# INetSim: HTTP/HTTPS 등 가짜 응답
#   /etc/inetsim/inetsim.conf 에서
#     service_bind_address 192.168.85.1
#     dns_default_ip        192.168.85.1  (DNS는 dnsmasq가 담당하므로 inetsim dns는 꺼도 됨)
sudo sed -i 's/^ENABLED=0/ENABLED=1/' /etc/default/inetsim
sudo systemctl enable --now inetsim
```
검증 (Infected에서):
```bash
nslookup example.com          # → 192.168.85.1
wget -qO- http://example.com/ # → INetSim 기본 페이지
```

### 4단계: Infected 수집 환경 (인터넷 필요 → 임시 NAT로 설치 후 격리)
```bash
# (임시 NAT 어댑터로 인터넷 확보 후)
git clone <repo> ~/Capstone && cd ~/Capstone
./scripts/setup.sh                                   # fuse3 + venv + pip
sudo apt install -y bpfcc-tools python3-bpfcc libbpfcc linux-headers-$(uname -r)  # eBPF(BCC)
sudo python3 -c "from bcc import BPF; print('bcc OK')"
# 설치 후 임시 NAT 제거 → 다시 격리
```

### 5단계: 샘플 배치 & 스냅샷
- 샘플: `~/malware/<FAMILY>/<sha256>.elf` (실행권한 없이 보관, SHA256 파일명으로 provenance)
- 격리 확인 후 **clean-ready 스냅샷** (Infected/Sandbox 각각)
- Sandbox는 이후 **절대 복원하지 않음** (백업 저장소)

### 6단계: 수집 루프 (샘플 1개당)
```bash
cd ~/Capstone

# ① 실행 가능한(x86-64) 샘플 확인
scripts/run_sample.sh <FAMILY> --list

# ② 수집 (패밀리 인자 자동, --as-user로 마운트 접근)
scripts/run_sample.sh <FAMILY> <SHA8>

# ③ 성공 확인: "파일 변경 감지됨" + 이벤트 수백~수천
ls -la ~/guardfs_runtime/underlay/attack_target/     # 암호화/랜섬노트 확인

# ④ 백업 (복원 전 필수!)
scp -O -o StrictHostKeyChecking=no \
    ~/guardfs_runtime/collect/<run_id>.* songjiwoo@192.168.85.1:~/collected/

# ⑤ Infected 스냅샷 복원 → 다음 샘플
```

**내부 동작** (`run_sample.sh` → `collect_one.sh`):
1. GuardFS를 `--collect-only`로 마운트 (탐지·차단 없이 순수 로깅)
2. 마운트 안 `attack_target/`에 테스트 파일 20종(64KB) 생성 + 실행 전 해시
3. eBPF 수집기(`models/dynamic/collect/ebpf_collector.py`)가 **프로브 등록 후** 샘플을 `infected` 권한으로 실행, 프로세스+자손 추적
4. eBPF/FUSE 두 관점 JSONL 저장, 실행 후 해시로 파일 변경 확인, 언마운트

### 7단계: 패밀리별 실행 인자 (확인된 것)
| 패밀리 | 인자 |
|--------|------|
| lockbit / Babuk / IceFire / Conti / BrainCipher | `<경로>` (위치) |
| AvosLocker | `50 <경로>` |
| HelloKitty | (libcrypto 심링크) + `-m 50 <경로>` |
| MONTI / REvil | `--path <경로>` |
| Akira(akira_v2) | `--path <경로> --id <BuildID> --ep 50` |
| INCRansom | `--dir <경로>` |
| Interlock | `--directory <경로>` |
| BlackCat / blackcat | `--access-token ANY_TOKEN -p <경로> --verbose` |
| wiper | (인자 없음) |
| Hive / Qilin / Royal / BlackSuit | 비밀값·arch 이슈로 조건부/스킵 |
| BlackBasta / BlackMatter / DarkSide / ESXi_misc / DarkRadiation | ESXi/설정 의존, 스킵 |

> 새 패밀리는 실행 전 usage 확인:
> ```bash
> strings -n5 ~/malware/<FAMILY>/*.elf | grep -iE 'usage|--[a-z]|path|encrypt' | sort -u | head
> # Rust 계열은 --help가 안전(파싱만 하고 종료)
> ```

### 8단계: 이후 (모델링, 미진행)
```
raw JSONL  →  tools/lineage_to_csv.py  →  프로세스별 피처 CSV
             (O/C/D/W/E sum + 3-gram: OCO, COC, COO ...)
          →  정상(0)+악성(1) 결합  →  IsolationForest / RandomForest
          →  탐지율 / 오탐율 평가
```
- 피처는 **프로세스 단위**라 run 1개 = 여러 행 → 14개 run도 PoC로 충분
- 정상(benign)은 악성 없이 쉽게 다량 수집 가능(복원 불필요)

---

## 안전 원칙 (반드시)
1. **샘플이 있는 VM엔 절대 NAT/Bridged 연결 금지** (설치는 샘플 넣기 전에)
2. **수집 = 스냅샷 상태에서만**, 끝나면 복원
3. **백업 먼저, 복원 나중** — 안 그러면 데이터 유실
4. **Sandbox 스냅샷 복원 금지** (백업 저장소), 주기적으로 VM 밖(호스트)으로 사본
5. 공유 폴더/클립보드 OFF, VMware 최신 유지
6. 랜섬노트의 링크(.onion 등) 접속 금지 — 읽기만
