# NTFS Forensic Parser

대용량 NTFS 아티팩트(MFT, LogFile, UsnJrnl:$J)를 분석하는 디지털 포렌식 도구

## 특징

- **대용량 파일 지원**: 스트리밍 방식으로 메모리 효율적 처리
- **이미지 파일 지원**: E01/EWF, RAW, DD 이미지에서 직접 추출
- **타임스탬프**: UTC+9 (한국 시간) 기준 출력
- **출력 형식**: CSV, JSON, SQLite(.db) 지원
- **경로 복원**: MFT 기반 전체 경로 재구성

## 설치

```bash
pip install -r requirements.txt
```


## 기능 목록

### 이미지 추출 기능

| 기능 | 설명 |
|------|------|
| E01/EWF 이미지 지원 | EnCase E01 포맷 디스크 이미지에서 아티팩트 추출 |
| RAW/DD 이미지 지원 | Raw 디스크 이미지 지원 |
| $MFT 추출 | Master File Table 자동 추출 |
| $LogFile 추출 | NTFS 트랜잭션 로그 자동 추출 |
| $UsnJrnl:$J 추출 | USN 변경 저널 추출 (Attribute List 지원) |
| NTFS 파티션 자동 탐지 | MBR/GPT 파티션 테이블 파싱 |
| 특정 파티션 선택 | `-p` 옵션으로 특정 파티션만 처리 |
| 올인원 추출+분석 | `extract-analyze` 명령으로 추출과 DB 분석 한번에 |

### MFT 분석 기능

| 기능 | 옵션 | 설명 |
|------|------|------|
| $MFT 파싱 | `-i, --input` | MFT 엔트리 전체 파싱 |
| 삭제된 파일 포함 | 기본값 | 삭제된 엔트리도 분석 |
| 활성 파일만 | `--active-only` | 사용 중인 엔트리만 분석 |
| 전체 경로 복원 | `--include-path` | 부모 참조를 통한 전체 경로 재구성 |
| $STANDARD_INFORMATION | 자동 | 생성/수정/접근 시간 파싱 |
| $FILE_NAME | 자동 | 파일명, 부모 참조, 타임스탬프 파싱 |
| $DATA | 자동 | 파일 크기, Resident/Non-resident 구분 |

### UsnJrnl 분석 기능

| 기능 | 옵션 | 설명 |
|------|------|------|
| $J 파싱 | `-i, --input` | USN 변경 저널 레코드 파싱 |
| USN v2/v3/v4 지원 | 자동 | 모든 USN 레코드 버전 지원 |
| 스트리밍 처리 | 자동 | 대용량 파일 메모리 효율적 처리 |
| 제로 영역 스킵 | 자동 | Sparse 영역 빠르게 건너뛰기 |
| MFT 경로 연동 | `--mft` | MFT 정보로 전체 경로 복원 |
| 이벤트 해석 | 자동 | 파일 생성/삭제/수정/이름변경 등 해석 |

### 출력 형식

| 형식 | 옵션 | 설명 |
|------|------|------|
| CSV | `-f csv` | 엑셀 호환 CSV (UTF-8 BOM) |
| JSON | `-f json` | JSON 배열 형식 |
| SQLite | `-f sqlite` | .db 파일 (인덱스 자동 생성) |

## 사용법

### 이미지에서 추출 + DB 분석
```bash
# 기본 (SQLite DB로 출력)
python .\ntfs_parser.py extract-analyze --image [Image File Path] -o [Output Directory Path]

# 특정 파티션만 처리
python .\ntfs_parser.py extract-analyze --image [Image File Path] -o [Output Directory Path] -p 0

# CSV로 출력
python .\ntfs_parser.py extract-analyze --image [Image File Path] -o [Output Directory Path] -f csv

# 임시 파일 유지
python .\ntfs_parser.py extract-analyze --image [Image File Path] -o [Output Directory Path] --keep-temp

# 특정 아티팩트 스킵
python .\ntfs_parser.py extract-analyze --image [Image File Path] -o [Output Directory Path] --skip-logfile
```

### 이미지에서 아티팩트 추출만
```bash
# 전체 파티션 추출
python .\ntfs_parser.py extract --image [Image File Path] -o [Output Directory Path]

# 특정 파티션만 추출
python .\ntfs_parser.py extract --image [Image File Path] -o [Output Directory Path] -p 0
```

### MFT 분석
```bash
# CSV 출력
python .\ntfs_parser.py parse-mft -i [Artifact Path] -o mft_result.csv

# SQLite 출력
python .\ntfs_parser.py parse-mft -i [Artifact Path] -o [Output File Path] -f sqlite

# 활성 파일만
python .\ntfs_parser.py parse-mft -i [Artifact Path] -o [Output File Path] --active-only
```

### UsnJrnl:$J 분석
```bash
# 기본 파싱
python .\ntfs_parser.py parse-usnjrnl -i [Artifact Path] -o usnjrnl_result.csv

# MFT 경로 연동
python .\ntfs_parser.py parse-usnjrnl -i [Artifact Path] -o usnjrnl_result.csv --mft $MFT

# SQLite 출력
python .\ntfs_parser.py parse-usnjrnl -i [Artifact Path] -o usnjrnl_result.db -f sqlite
```

### LogFile 분석
```bash
python .\ntfs_parser.py parse-logfile -i [Artifact Path] -o logfile_result.csv
```

### 통합 분석
```bash
python .\ntfs_parser.py analyze --mft [MFT Path] --usnjrnl [UsnJrnl Path] --logfile [LogFile Path] -o [Output File Path]
```

## 출력 필드

### MFT 출력 필드

| 필드 | 설명 |
|------|------|
| EntryNumber | MFT 엔트리 번호 |
| SequenceNumber | 시퀀스 번호 |
| InUse | 사용 중 여부 |
| IsDirectory | 디렉토리 여부 |
| FileName | 파일명 |
| FullPath | 전체 경로 |
| FileAttr | 파일 속성 (Hidden, System 등) |
| SI_Created | $STANDARD_INFORMATION 생성 시간 |
| SI_Modified | $STANDARD_INFORMATION 수정 시간 |
| SI_MFTModified | $STANDARD_INFORMATION MFT 수정 시간 |
| SI_Accessed | $STANDARD_INFORMATION 접근 시간 |
| FN_Created | $FILE_NAME 생성 시간 |
| FN_Modified | $FILE_NAME 수정 시간 |
| FN_MFTModified | $FILE_NAME MFT 수정 시간 |
| FN_Accessed | $FILE_NAME 접근 시간 |
| DataSize | 파일 크기 |
| IsResident | Resident 여부 |

### UsnJrnl 출력 필드

| 필드 | 설명 |
|------|------|
| Timestamp | 이벤트 발생 시간 (UTC+9) |
| FileName | 파일명 |
| FullPath | 전체 경로 (MFT 연동 시) |
| Event | 이벤트 유형 (FILE_CREATE, FILE_DELETE 등) |
| FileAttr | 파일 속성 |
| USN | USN 번호 |
| SourceInfo | 소스 정보 |
| SecurityID | 보안 ID |

## 이벤트 유형 (UsnJrnl)

| 이벤트 | 설명 |
|--------|------|
| FILE_CREATE | 파일 생성 |
| FILE_DELETE | 파일 삭제 |
| DATA_EXTEND | 데이터 확장 |
| DATA_OVERWRITE | 데이터 덮어쓰기 |
| DATA_TRUNCATION | 데이터 축소 |
| RENAME_OLD_NAME | 이름 변경 (이전 이름) |
| RENAME_NEW_NAME | 이름 변경 (새 이름) |
| SECURITY_CHANGE | 보안 속성 변경 |
| BASIC_INFO_CHANGE | 기본 정보 변경 |
| CLOSE | 파일 닫기 |

## 요구사항

- Python 3.8+
- construct >= 2.10.68
- tqdm >= 4.65.0
- libewf-python >= 20231119 (E01 이미지 지원, 선택)
