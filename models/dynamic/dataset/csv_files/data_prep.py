import pandas as pd
import re
import os
from collections import deque

def process_single_log(file_path, malware_pids):
    """단일 로그 파일을 분석하여 모든 3단계 패턴 피처를 추출합니다."""
    process_data = {}
    
    # 사용자가 요청한 32가지 모든 패턴 리스트
    patterns = [
        'CCC', 'CCD', 'CCO', 'CDC', 'CDD', 'CDO', 'COC', 'COD', 'COO', 
        'DCC', 'DCD', 'DCO', 'DDC', 'DDD', 'DDO', 'DOC', 'DOD', 'DOO', 
        'EEE', 'EEO', 'EOE', 'EOO', 'OCC', 'OCD', 'OCO', 'ODC', 'ODD', 
        'ODO', 'OEE', 'OOC', 'OOD', 'OOO'
    ]
    
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            # 정규식 업데이트: O, C, D 뿐만 아니라 E(Encrypt)도 캡처함 [OCDE]
            match = re.match(r'\[(\d+)\]\s+\S+\s+([OCDE])\s+(.+)', line)
            if not match: continue
            
            pid, action, path = match.groups()
            
            if pid not in process_data:
                # 기본 통계 초기화 (O_sum, C_sum, D_sum, E_sum)
                process_data[pid] = {
                    'stats': {
                        'O_sum': 0, 'C_sum': 0, 'D_sum': 0, 'E_sum': 0,
                        'Is_System_Path': 0, 'Is_Test_Path': 0
                    },
                    'history': deque(maxlen=3)
                }
                # 32개 모든 패턴 카운터를 0으로 초기화
                for p in patterns: 
                    process_data[pid]['stats'][p] = 0

            stats = process_data[pid]['stats']
            stats[f'{action}_sum'] += 1
            
            # 경로 특성 (시스템 경로 vs 테스트 경로)
            if any(x in path for x in ['/dev/', '/run/', '/etc/', '/sys/']): stats['Is_System_Path'] = 1
            if '/test_files/' in path: stats['Is_Test_Path'] = 1
            
            # 슬라이딩 윈도우로 패턴 카운트
            history = process_data[pid]['history']
            history.append(action)
            if len(history) == 3:
                curr_p = "".join(history)
                if curr_p in patterns: 
                    stats[curr_p] += 1

    # 리스트로 변환하여 DataFrame 생성
    feature_list = []
    for pid, data in process_data.items():
        row = {'PID': pid}
        row.update(data['stats'])
        # 이 파일 환경에서 지정한 악성 PID만 1로 라벨링
        row['Label'] = 1 if pid in malware_pids else 0
        feature_list.append(row)
        
    return pd.DataFrame(feature_list)

# --- 실제 사용 방법 ---

# 1. 지금 분석할 로그 파일 경로 (파일을 바꿀 때마다 여기만 수정하세요)
file_to_process = r"C:\Users\seelh\Documents\Capstone\Capstone\detect_dynamic\dataset3\logs2\f864922f_REvil.log"

# 2. '해당 파일'에서만 악성인 PID (로그 확인 후 매번 수정하세요)
current_malware_pids = ['5077']

# 3. 데이터 추출 및 누적 저장
save_path = r"C:\Users\seelh\Documents\Capstone\Capstone\detect_dynamic\dataset\csv_files\malware_dataset.csv"

new_df = process_single_log(file_to_process, current_malware_pids)

if os.path.exists(save_path):
    final_df = pd.concat([pd.read_csv(save_path), new_df], ignore_index=True)
else:
    final_df = new_df

# 최종 CSV 저장
final_df.to_csv(save_path, index=False)
print(f"패턴 분석 완료! 현재 데이터셋 총 행수: {len(final_df)}")