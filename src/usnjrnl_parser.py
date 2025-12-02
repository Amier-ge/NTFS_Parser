import struct
import os
from typing import Generator, Optional, Dict
from pathlib import Path
from dataclasses import dataclass

from .constants import (
    UsnReason, FileAttrFlags,
    filetime_to_datetime, format_timestamp, format_file_attr,
    format_usn_reason, format_file_reference, parse_file_reference
)


@dataclass
class UsnRecord:
    # 레코드 메타데이터
    record_length: int = 0
    major_version: int = 0
    minor_version: int = 0

    # 파일 정보
    file_reference: int = 0
    parent_file_reference: int = 0
    usn: int = 0

    # 타임스탬프
    timestamp: str = ""
    timestamp_raw: int = 0

    # 변경 정보
    reason: int = 0
    source_info: int = 0
    security_id: int = 0
    file_attributes: int = 0

    # 파일명
    filename: str = ""
    filename_length: int = 0
    filename_offset: int = 0

    # 추가 정보 (v3/v4)
    extra_info1: int = 0
    extra_info2: int = 0

    @property
    def event(self) -> str:
        return format_usn_reason(self.reason)

    @property
    def file_attr_str(self) -> str:
        return format_file_attr(self.file_attributes)

    @property
    def file_ref_str(self) -> str:
        return format_file_reference(self.file_reference)

    @property
    def parent_ref_str(self) -> str:
        return format_file_reference(self.parent_file_reference)


class UsnJrnlParser:

    # 버퍼 크기 (1MB)
    BUFFER_SIZE = 1024 * 1024

    # USN_RECORD_V2 최소 크기
    MIN_RECORD_SIZE_V2 = 60

    # USN_RECORD_V3 최소 크기
    MIN_RECORD_SIZE_V3 = 76

    def __init__(self, usnjrnl_path: str):
        self.usnjrnl_path = Path(usnjrnl_path)
        self.total_records = 0
        self.processed_bytes = 0
        self.file_size = 0

    def iter_records(self, skip_zeros: bool = True) -> Generator[UsnRecord, None, None]:

        self.file_size = self.usnjrnl_path.stat().st_size

        with open(self.usnjrnl_path, 'rb') as f:
            buffer = b''

            while True:
                # 버퍼 채우기
                chunk = f.read(self.BUFFER_SIZE)
                if not chunk:
                    break

                buffer += chunk

                # 버퍼에서 레코드 파싱
                while len(buffer) >= self.MIN_RECORD_SIZE_V2:
                    # 제로 영역 스킵
                    if skip_zeros and buffer[:8] == b'\x00' * 8:
                        # 연속된 제로 찾기
                        zero_end = 0
                        for i in range(0, len(buffer) - 8, 8):
                            if buffer[i:i + 8] != b'\x00' * 8:
                                zero_end = i
                                break
                        else:
                            zero_end = len(buffer)

                        # 8바이트 정렬
                        zero_end = (zero_end // 8) * 8
                        if zero_end > 0:
                            self.processed_bytes += zero_end
                            buffer = buffer[zero_end:]
                            continue
                        else:
                            # 전체가 제로
                            self.processed_bytes += len(buffer)
                            buffer = b''
                            break

                    # 레코드 크기 확인
                    record_length = struct.unpack('<I', buffer[0:4])[0]

                    # 유효성 검사
                    if record_length < self.MIN_RECORD_SIZE_V2 or record_length > 65536:
                        # 다음 유효한 레코드 검색
                        found = False
                        for i in range(8, len(buffer) - 8, 8):
                            potential_len = struct.unpack('<I', buffer[i:i + 4])[0]
                            if self.MIN_RECORD_SIZE_V2 <= potential_len <= 65536:
                                major = struct.unpack('<H', buffer[i + 4:i + 6])[0]
                                minor = struct.unpack('<H', buffer[i + 6:i + 8])[0]
                                if major in [2, 3, 4] and minor == 0:
                                    self.processed_bytes += i
                                    buffer = buffer[i:]
                                    found = True
                                    break

                        if not found:
                            self.processed_bytes += len(buffer) - self.MIN_RECORD_SIZE_V2
                            buffer = buffer[-self.MIN_RECORD_SIZE_V2:]
                        continue

                    # 버퍼에 전체 레코드가 있는지 확인
                    if len(buffer) < record_length:
                        break

                    # 레코드 파싱
                    record_data = buffer[:record_length]
                    record = self._parse_record(record_data)

                    if record:
                        self.total_records += 1
                        yield record

                    self.processed_bytes += record_length
                    buffer = buffer[record_length:]

    def _parse_record(self, data: bytes) -> Optional[UsnRecord]:
        if len(data) < self.MIN_RECORD_SIZE_V2:
            return None

        record = UsnRecord()
        record.record_length = struct.unpack('<I', data[0:4])[0]
        record.major_version = struct.unpack('<H', data[4:6])[0]
        record.minor_version = struct.unpack('<H', data[6:8])[0]

        # 버전별 파싱
        if record.major_version == 2:
            return self._parse_v2_record(data, record)
        elif record.major_version == 3:
            return self._parse_v3_record(data, record)
        elif record.major_version == 4:
            return self._parse_v4_record(data, record)
        else:
            return None

    def _parse_v2_record(self, data: bytes, record: UsnRecord) -> Optional[UsnRecord]:

        if len(data) < self.MIN_RECORD_SIZE_V2:
            return None

        try:
            record.file_reference = struct.unpack('<Q', data[8:16])[0]
            record.parent_file_reference = struct.unpack('<Q', data[16:24])[0]
            record.usn = struct.unpack('<Q', data[24:32])[0]
            record.timestamp_raw = struct.unpack('<Q', data[32:40])[0]
            record.timestamp = format_timestamp(filetime_to_datetime(record.timestamp_raw))
            record.reason = struct.unpack('<I', data[40:44])[0]
            record.source_info = struct.unpack('<I', data[44:48])[0]
            record.security_id = struct.unpack('<I', data[48:52])[0]
            record.file_attributes = struct.unpack('<I', data[52:56])[0]
            record.filename_length = struct.unpack('<H', data[56:58])[0]
            record.filename_offset = struct.unpack('<H', data[58:60])[0]

            # 파일명 추출
            if record.filename_offset + record.filename_length <= len(data):
                name_data = data[record.filename_offset:record.filename_offset + record.filename_length]
                try:
                    record.filename = name_data.decode('utf-16-le')
                except:
                    record.filename = name_data.decode('utf-16-le', errors='replace')

            return record

        except struct.error:
            return None

    def _parse_v3_record(self, data: bytes, record: UsnRecord) -> Optional[UsnRecord]:

        if len(data) < self.MIN_RECORD_SIZE_V3:
            return None

        try:
            # V3는 128비트 파일 참조 사용
            record.file_reference = struct.unpack('<Q', data[8:16])[0]
            record.extra_info1 = struct.unpack('<Q', data[16:24])[0]
            record.parent_file_reference = struct.unpack('<Q', data[24:32])[0]
            record.extra_info2 = struct.unpack('<Q', data[32:40])[0]
            record.usn = struct.unpack('<Q', data[40:48])[0]
            record.timestamp_raw = struct.unpack('<Q', data[48:56])[0]
            record.timestamp = format_timestamp(filetime_to_datetime(record.timestamp_raw))
            record.reason = struct.unpack('<I', data[56:60])[0]
            record.source_info = struct.unpack('<I', data[60:64])[0]
            record.security_id = struct.unpack('<I', data[64:68])[0]
            record.file_attributes = struct.unpack('<I', data[68:72])[0]
            record.filename_length = struct.unpack('<H', data[72:74])[0]
            record.filename_offset = struct.unpack('<H', data[74:76])[0]

            if record.filename_offset + record.filename_length <= len(data):
                name_data = data[record.filename_offset:record.filename_offset + record.filename_length]
                try:
                    record.filename = name_data.decode('utf-16-le')
                except:
                    record.filename = name_data.decode('utf-16-le', errors='replace')

            return record

        except struct.error:
            return None

    def _parse_v4_record(self, data: bytes, record: UsnRecord) -> Optional[UsnRecord]:

        # V4는 V3와 유사하지만 추가 필드가 있음
        return self._parse_v3_record(data, record)

    @property
    def progress(self) -> float:

        if self.file_size == 0:
            return 0.0
        return min(1.0, self.processed_bytes / self.file_size)


class UsnJrnlParserWithMFT(UsnJrnlParser):

    def __init__(self, usnjrnl_path: str, mft_path: str = None):
        super().__init__(usnjrnl_path)
        self.mft_path = mft_path
        self.path_cache: Dict[int, str] = {}

    def build_path_cache_from_mft(self):
        if not self.mft_path or not Path(self.mft_path).exists():
            return

        from .mft_parser import MFTParser
        parser = MFTParser(self.mft_path)
        parser.build_path_cache()
        self.path_cache = parser.path_cache

    def get_full_path(self, file_ref: int) -> str:
        entry_number, _ = parse_file_reference(file_ref)
        return self.path_cache.get(entry_number, "")


def parse_usnjrnl(usnjrnl_path: str, output_path: str, mft_path: str = None,
                  output_format: str = 'csv', include_path: bool = True):
    import csv
    import json
    import sqlite3

    if mft_path and include_path:
        parser = UsnJrnlParserWithMFT(usnjrnl_path, mft_path)
        parser.build_path_cache_from_mft()
    else:
        parser = UsnJrnlParser(usnjrnl_path)

    headers = [
        'Timestamp', 'FileName', 'FullPath', 'Event', 'FileAttr',
        'USN', 'SourceInfo', 'SecurityID'
    ]

    if output_format == 'csv':
        with open(output_path, 'w', newline='', encoding='utf-8-sig') as f:
            writer = csv.writer(f)
            writer.writerow(headers)

            for record in parser.iter_records():
                if include_path and isinstance(parser, UsnJrnlParserWithMFT):
                    full_path = parser.get_full_path(record.file_reference)
                else:
                    full_path = ""

                row = [
                    record.timestamp,
                    record.filename,
                    full_path,
                    record.event,
                    record.file_attr_str,
                    record.usn,
                    record.source_info,
                    record.security_id
                ]
                writer.writerow(row)

    elif output_format == 'json':
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write('[\n')
            first = True

            for record in parser.iter_records():
                if not first:
                    f.write(',\n')
                first = False

                if include_path and isinstance(parser, UsnJrnlParserWithMFT):
                    full_path = parser.get_full_path(record.file_reference)
                else:
                    full_path = ""

                obj = {
                    'Timestamp': record.timestamp,
                    'FileName': record.filename,
                    'FullPath': full_path,
                    'Event': record.event,
                    'FileAttr': record.file_attr_str,
                    'USN': record.usn,
                    'SourceInfo': record.source_info,
                    'SecurityID': record.security_id
                }
                f.write('  ' + json.dumps(obj, ensure_ascii=False))

            f.write('\n]')

    elif output_format == 'sqlite':
        # .db 확장자 보장
        if not output_path.endswith('.db'):
            output_path = output_path.rsplit('.', 1)[0] + '.db' if '.' in output_path else output_path + '.db'

        conn = sqlite3.connect(output_path)
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS usnjrnl (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                Timestamp TEXT,
                FileName TEXT,
                FullPath TEXT,
                Event TEXT,
                FileAttr TEXT,
                USN INTEGER,
                SourceInfo INTEGER,
                SecurityID INTEGER
            )
        ''')

        batch = []
        for record in parser.iter_records():
            if include_path and isinstance(parser, UsnJrnlParserWithMFT):
                full_path = parser.get_full_path(record.file_reference)
            else:
                full_path = ""

            batch.append((
                record.timestamp,
                record.filename,
                full_path,
                record.event,
                record.file_attr_str,
                record.usn,
                record.source_info,
                record.security_id
            ))

            if len(batch) >= 10000:
                cursor.executemany('''
                    INSERT INTO usnjrnl (Timestamp, FileName, FullPath, Event, FileAttr, USN, SourceInfo, SecurityID)
                    VALUES (?,?,?,?,?,?,?,?)
                ''', batch)
                conn.commit()
                batch = []

        if batch:
            cursor.executemany('''
                INSERT INTO usnjrnl (Timestamp, FileName, FullPath, Event, FileAttr, USN, SourceInfo, SecurityID)
                VALUES (?,?,?,?,?,?,?,?)
            ''', batch)
            conn.commit()

        # 인덱스 생성
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_usn_timestamp ON usnjrnl(Timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_usn_filename ON usnjrnl(FileName)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_usn_event ON usnjrnl(Event)')
        conn.commit()
        conn.close()


def parse_usnjrnl_streaming(usnjrnl_path: str, output_path: str,
                            callback=None, output_format: str = 'csv'):
    import csv

    parser = UsnJrnlParser(usnjrnl_path)

    if output_format == 'csv':
        with open(output_path, 'w', newline='', encoding='utf-8-sig') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Timestamp', 'FileName', 'Event', 'FileAttr', 'USN'
            ])

            count = 0
            for record in parser.iter_records():
                writer.writerow([
                    record.timestamp,
                    record.filename,
                    record.event,
                    record.file_attr_str,
                    record.usn
                ])

                count += 1
                if callback and count % 10000 == 0:
                    callback(parser.progress, count)

            if callback:
                callback(1.0, count)

    return parser.total_records
