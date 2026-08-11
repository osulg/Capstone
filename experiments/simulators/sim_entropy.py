import os

# 1. 테스트용 대상 원본 파일 경로 지정
# 경로 설정 후 실행
path = os.path.expanduser("")

# 2. 만약 부모 디렉토리가 없다면 안전하게 생성
os.makedirs(os.path.dirname(path), exist_ok=True)

# 3. 테스트를 위한 일반 텍스트 데이터 먼저 기록
with open(path, "w", encoding="utf-8") as f:
    f.write("int main() { printf('Hello World'); return 0; }")

print(f"[PREPARE] 정상 파일 생성 완료: {path}")

# 4. 외부 패키지(crypto) 대신 파이썬 내장 기능을 사용하여 고엔트로피 바이너리 생성
# os.urandom은 랜섬웨어가 암호화한 것과 통계적으로 완전히 동일한 무작위 바이트를 만듭니다.
high_entropy_data = os.urandom(1024) 

# 5. 고엔트로피 데이터 주입 (엔트로피 경량 탐지 트리거용)
with open(path, "wb") as f:
    f.write(high_entropy_data)

print(f"[ATTACK] 고엔트로피 데이터 쓰기 완료! GuardFS 로그를 확인하세요.")