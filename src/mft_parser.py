import struct
import os
from typing import Generator, Optional, Dict, List, BinaryIO
from pathlib import Path
from dataclasses import dataclass, field

from .constants import (
    MFT_ENTRY_SIZE, MFT_SIGNATURE, MFT_SIGNATURE_BAD,
    AttrType, FileAttrFlags, MftRecordFlags, FileNamespace,
    filetime_to_datetime, format_timestamp, format_file_attr,
    format_file_reference, parse_file_reference
)


@dataclass
class MFTRecord:
    entry_number: int
    sequence_number: int = 0
    flags: int = 0
    in_use: bool = False
    is_directory: bool = False

    # $STANDARD_INFORMATION
    si_created: str = ""
    si_modified: str = ""
    si_mft_modified: str = ""
    si_accessed: str = ""
    si_flags: int = 0

    # $FILE_NAME (가장 긴 이름 사용)
    filename: str = ""
    parent_ref: int = 0
    fn_created: str = ""
    fn_modified: str = ""
    fn_mft_modified: str = ""
    fn_accessed: str = ""
    fn_flags: int = 0
    fn_allocated_size: int = 0
    fn_real_size: int = 0

    # 추가 정보
    data_size: int = 0
    is_resident: bool = True

    # 경로 (나중에 계산)
    full_path: str = ""


class MFTEntry:

    def __init__(self, data: bytes, entry_number: int):
        self.data = data
        self.entry_number = entry_number
        self.attributes = []
        self.is_valid = False
        self.flags = 0
        self.sequence = 0

    def parse(self) -> bool:
        if len(self.data) < 48:
            return False

        # 시그니처 확인
        signature = self.data[0:4]
        if signature not in [MFT_SIGNATURE, MFT_SIGNATURE_BAD]:
            return False

        if signature == MFT_SIGNATURE_BAD:
            return False

        # Fixup 배열 적용
        fixup_offset = struct.unpack('<H', self.data[4:6])[0]
        fixup_count = struct.unpack('<H', self.data[6:8])[0]

        if fixup_count > 0 and fixup_offset + fixup_count * 2 <= len(self.data):
            self._apply_fixup(fixup_offset, fixup_count)

        # 헤더 파싱
        self.sequence = struct.unpack('<H', self.data[16:18])[0]
        self.flags = struct.unpack('<H', self.data[22:24])[0]

        # 속성 시작 오프셋
        attr_offset = struct.unpack('<H', self.data[20:22])[0]
        used_size = struct.unpack('<I', self.data[24:28])[0]

        # 속성 파싱
        self._parse_attributes(attr_offset, used_size)

        self.is_valid = True
        return True

    def _apply_fixup(self, offset: int, count: int):
        data = bytearray(self.data)
        fixup_signature = data[offset:offset + 2]

        for i in range(1, count):
            fixup_value = data[offset + i * 2:offset + i * 2 + 2]
            sector_end = (i * 512) - 2

            if sector_end + 2 <= len(data):
                # 섹터 끝의 시그니처 확인 및 교체
                data[sector_end:sector_end + 2] = fixup_value

        self.data = bytes(data)

    def _parse_attributes(self, start_offset: int, max_offset: int):
        offset = start_offset

        while offset + 4 <= len(self.data) and offset < max_offset:
            attr_type = struct.unpack('<I', self.data[offset:offset + 4])[0]

            if attr_type == 0xFFFFFFFF:  # End marker
                break

            if offset + 8 > len(self.data):
                break

            attr_length = struct.unpack('<I', self.data[offset + 4:offset + 8])[0]

            if attr_length == 0 or attr_length > len(self.data) - offset:
                break

            attr_data = self.data[offset:offset + attr_length]
            attr = self._parse_attribute(attr_type, attr_data)
            if attr:
                self.attributes.append(attr)

            offset += attr_length

    def _parse_attribute(self, attr_type: int, data: bytes) -> Optional[dict]:
        if len(data) < 16:
            return None

        attr = {
            'type': attr_type,
            'length': len(data),
            'non_resident': bool(data[8]),
            'name_length': data[9],
            'name_offset': struct.unpack('<H', data[10:12])[0],
            'flags': struct.unpack('<H', data[12:14])[0],
            'id': struct.unpack('<H', data[14:16])[0],
        }

        # 속성 이름 추출
        if attr['name_length'] > 0:
            name_start = attr['name_offset']
            name_end = name_start + attr['name_length'] * 2
            if name_end <= len(data):
                try:
                    attr['name'] = data[name_start:name_end].decode('utf-16-le')
                except:
                    attr['name'] = ''
        else:
            attr['name'] = ''

        if attr['non_resident']:
            self._parse_non_resident_attr(attr, data)
        else:
            self._parse_resident_attr(attr, data)

        # 타입별 추가 파싱
        if attr_type == AttrType.STANDARD_INFORMATION:
            self._parse_standard_info(attr)
        elif attr_type == AttrType.FILE_NAME:
            self._parse_filename(attr)
        elif attr_type == AttrType.DATA:
            pass  # 데이터 런은 이미 파싱됨

        return attr

    def _parse_resident_attr(self, attr: dict, data: bytes):
        if len(data) < 24:
            return

        content_size = struct.unpack('<I', data[16:20])[0]
        content_offset = struct.unpack('<H', data[20:22])[0]

        if content_offset + content_size <= len(data):
            attr['data'] = data[content_offset:content_offset + content_size]
        else:
            attr['data'] = b''

    def _parse_non_resident_attr(self, attr: dict, data: bytes):
        if len(data) < 48:  # 최소 크기 완화
            return

        attr['start_vcn'] = struct.unpack('<Q', data[16:24])[0]
        attr['end_vcn'] = struct.unpack('<Q', data[24:32])[0]
        attr['run_offset'] = struct.unpack('<H', data[32:34])[0]
        attr['compression_unit'] = struct.unpack('<H', data[34:36])[0]
        attr['allocated_size'] = struct.unpack('<Q', data[40:48])[0]

        # real_size와 initialized_size는 start_vcn이 0일 때만 존재
        if attr['start_vcn'] == 0 and len(data) >= 64:
            attr['real_size'] = struct.unpack('<Q', data[48:56])[0]
            attr['initialized_size'] = struct.unpack('<Q', data[56:64])[0]
        else:
            attr['real_size'] = attr['allocated_size']
            attr['initialized_size'] = attr['allocated_size']

        # 데이터 런 파싱
        run_offset = attr['run_offset']
        if run_offset < len(data):
            attr['data_runs'] = self._parse_data_runs(data[run_offset:])

    def _parse_data_runs(self, data: bytes) -> list:
        runs = []
        offset = 0
        current_cluster = 0

        while offset < len(data):
            header = data[offset]
            if header == 0:
                break

            length_size = header & 0x0F
            offset_size = (header >> 4) & 0x0F

            if length_size == 0:
                break

            if offset + 1 + length_size + offset_size > len(data):
                break

            # 길이 읽기 (unsigned)
            length_bytes = data[offset + 1:offset + 1 + length_size]
            run_length = int.from_bytes(length_bytes, 'little')

            # 오프셋 읽기 (signed)
            if offset_size > 0:
                offset_bytes = data[offset + 1 + length_size:offset + 1 + length_size + offset_size]
                # signed 변환을 수동으로 처리 (Python의 int.from_bytes signed 옵션이 특수한 경우 제대로 작동 안할 수 있음)
                run_offset = int.from_bytes(offset_bytes, 'little')
                # 최상위 비트가 1이면 음수 처리
                if offset_bytes[-1] & 0x80:
                    run_offset -= (1 << (offset_size * 8))
                current_cluster += run_offset

                runs.append({
                    'start_cluster': current_cluster,
                    'length': run_length,
                    'sparse': False
                })
            else:
                # Sparse run (offset_size == 0)
                runs.append({
                    'start_cluster': 0,
                    'length': run_length,
                    'sparse': True
                })

            offset += 1 + length_size + offset_size

        return runs

    def _parse_standard_info(self, attr: dict):
        """$STANDARD_INFORMATION 파싱"""
        data = attr.get('data', b'')
        if len(data) < 48:
            return

        attr['si_created'] = struct.unpack('<Q', data[0:8])[0]
        attr['si_modified'] = struct.unpack('<Q', data[8:16])[0]
        attr['si_mft_modified'] = struct.unpack('<Q', data[16:24])[0]
        attr['si_accessed'] = struct.unpack('<Q', data[24:32])[0]
        attr['si_flags'] = struct.unpack('<I', data[32:36])[0]

    def _parse_filename(self, attr: dict):
        """$FILE_NAME 파싱"""
        data = attr.get('data', b'')
        if len(data) < 66:
            return

        attr['parent_ref'] = struct.unpack('<Q', data[0:8])[0]
        attr['fn_created'] = struct.unpack('<Q', data[8:16])[0]
        attr['fn_modified'] = struct.unpack('<Q', data[16:24])[0]
        attr['fn_mft_modified'] = struct.unpack('<Q', data[24:32])[0]
        attr['fn_accessed'] = struct.unpack('<Q', data[32:40])[0]
        attr['fn_allocated_size'] = struct.unpack('<Q', data[40:48])[0]
        attr['fn_real_size'] = struct.unpack('<Q', data[48:56])[0]
        attr['fn_flags'] = struct.unpack('<I', data[56:60])[0]
        attr['fn_namespace'] = data[65]

        name_length = data[64]
        if len(data) >= 66 + name_length * 2:
            try:
                attr['filename'] = data[66:66 + name_length * 2].decode('utf-16-le')
            except:
                attr['filename'] = ''

    def to_record(self) -> Optional[MFTRecord]:
        if not self.is_valid:
            return None

        record = MFTRecord(
            entry_number=self.entry_number,
            sequence_number=self.sequence,
            flags=self.flags,
            in_use=bool(self.flags & MftRecordFlags.IN_USE),
            is_directory=bool(self.flags & MftRecordFlags.DIRECTORY)
        )

        # $STANDARD_INFORMATION 추출
        for attr in self.attributes:
            if attr['type'] == AttrType.STANDARD_INFORMATION:
                record.si_created = format_timestamp(filetime_to_datetime(attr.get('si_created', 0)))
                record.si_modified = format_timestamp(filetime_to_datetime(attr.get('si_modified', 0)))
                record.si_mft_modified = format_timestamp(filetime_to_datetime(attr.get('si_mft_modified', 0)))
                record.si_accessed = format_timestamp(filetime_to_datetime(attr.get('si_accessed', 0)))
                record.si_flags = attr.get('si_flags', 0)
                break

        # $FILE_NAME 추출 (WIN32 또는 WIN32_AND_DOS 우선)
        best_filename = None
        for attr in self.attributes:
            if attr['type'] == AttrType.FILE_NAME:
                namespace = attr.get('fn_namespace', 0)
                filename = attr.get('filename', '')

                if namespace in [FileNamespace.WIN32, FileNamespace.WIN32_AND_DOS]:
                    best_filename = attr
                    break
                elif namespace == FileNamespace.POSIX and best_filename is None:
                    best_filename = attr
                elif best_filename is None:
                    best_filename = attr

        if best_filename:
            record.filename = best_filename.get('filename', '')
            record.parent_ref = best_filename.get('parent_ref', 0)
            record.fn_created = format_timestamp(filetime_to_datetime(best_filename.get('fn_created', 0)))
            record.fn_modified = format_timestamp(filetime_to_datetime(best_filename.get('fn_modified', 0)))
            record.fn_mft_modified = format_timestamp(filetime_to_datetime(best_filename.get('fn_mft_modified', 0)))
            record.fn_accessed = format_timestamp(filetime_to_datetime(best_filename.get('fn_accessed', 0)))
            record.fn_flags = best_filename.get('fn_flags', 0)
            record.fn_allocated_size = best_filename.get('fn_allocated_size', 0)
            record.fn_real_size = best_filename.get('fn_real_size', 0)

        # $DATA 크기
        for attr in self.attributes:
            if attr['type'] == AttrType.DATA and attr.get('name', '') == '':
                record.is_resident = not attr.get('non_resident', False)
                if attr.get('non_resident', False):
                    record.data_size = attr.get('real_size', 0)
                else:
                    record.data_size = len(attr.get('data', b''))
                break

        return record


class MFTParser:

    def __init__(self, mft_path: str, entry_size: int = MFT_ENTRY_SIZE):
        self.mft_path = Path(mft_path)
        self.entry_size = entry_size
        self.total_entries = 0
        self.path_cache: Dict[int, str] = {}

    def get_total_entries(self) -> int:
        file_size = self.mft_path.stat().st_size
        return file_size // self.entry_size

    def iter_entries(self, include_deleted: bool = True) -> Generator[MFTRecord, None, None]:
        self.total_entries = self.get_total_entries()

        with open(self.mft_path, 'rb') as f:
            entry_number = 0

            while True:
                data = f.read(self.entry_size)
                if len(data) < self.entry_size:
                    break

                entry = MFTEntry(data, entry_number)
                if entry.parse():
                    record = entry.to_record()
                    if record:
                        if include_deleted or record.in_use:
                            yield record

                entry_number += 1

    def build_path_cache(self):
        # 첫 번째 패스: 모든 엔트리의 부모 관계 수집
        parent_map = {}
        name_map = {}

        with open(self.mft_path, 'rb') as f:
            entry_number = 0

            while True:
                data = f.read(self.entry_size)
                if len(data) < self.entry_size:
                    break

                entry = MFTEntry(data, entry_number)
                if entry.parse():
                    record = entry.to_record()
                    if record and record.in_use:
                        parent_entry, _ = parse_file_reference(record.parent_ref)
                        parent_map[entry_number] = parent_entry
                        name_map[entry_number] = record.filename

                entry_number += 1

        # 경로 계산
        def get_path(entry_num: int, visited: set = None) -> str:
            if visited is None:
                visited = set()

            if entry_num in self.path_cache:
                return self.path_cache[entry_num]

            if entry_num not in name_map:
                return ""

            if entry_num in visited:  # 순환 참조 방지
                return ""

            visited.add(entry_num)

            name = name_map[entry_num]
            parent = parent_map.get(entry_num, 0)

            if entry_num == 5:  # Root directory
                path = "\\"
            elif parent == 5 or parent == entry_num:
                path = f"\\{name}"
            else:
                parent_path = get_path(parent, visited)
                path = f"{parent_path}\\{name}" if parent_path else f"\\{name}"

            self.path_cache[entry_num] = path
            return path

        for entry_num in name_map:
            get_path(entry_num)

    def iter_entries_with_paths(self, include_deleted: bool = True) -> Generator[MFTRecord, None, None]:
        # 먼저 경로 캐시 빌드
        self.build_path_cache()

        # 다시 순회하면서 경로 추가
        for record in self.iter_entries(include_deleted):
            record.full_path = self.path_cache.get(record.entry_number, "")
            yield record


def parse_mft_file(mft_path: str, output_path: str, include_deleted: bool = True,
                   output_format: str = 'csv', include_path: bool = True):
    import csv
    import json
    import sqlite3

    parser = MFTParser(mft_path)

    headers = [
        'EntryNumber', 'SequenceNumber', 'InUse', 'IsDirectory',
        'FileName', 'FullPath', 'FileAttr',
        'SI_Created', 'SI_Modified', 'SI_MFTModified', 'SI_Accessed',
        'FN_Created', 'FN_Modified', 'FN_MFTModified', 'FN_Accessed',
        'DataSize', 'IsResident'
    ]

    if output_format == 'csv':
        with open(output_path, 'w', newline='', encoding='utf-8-sig') as f:
            writer = csv.writer(f)
            writer.writerow(headers)

            if include_path:
                entries = parser.iter_entries_with_paths(include_deleted)
            else:
                entries = parser.iter_entries(include_deleted)

            for record in entries:
                row = [
                    record.entry_number,
                    record.sequence_number,
                    record.in_use,
                    record.is_directory,
                    record.filename,
                    record.full_path if include_path else "",
                    format_file_attr(record.si_flags),
                    record.si_created,
                    record.si_modified,
                    record.si_mft_modified,
                    record.si_accessed,
                    record.fn_created,
                    record.fn_modified,
                    record.fn_mft_modified,
                    record.fn_accessed,
                    record.data_size,
                    record.is_resident
                ]
                writer.writerow(row)

    elif output_format == 'json':
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write('[\n')
            first = True

            if include_path:
                entries = parser.iter_entries_with_paths(include_deleted)
            else:
                entries = parser.iter_entries(include_deleted)

            for record in entries:
                if not first:
                    f.write(',\n')
                first = False

                obj = {
                    'EntryNumber': record.entry_number,
                    'SequenceNumber': record.sequence_number,
                    'InUse': record.in_use,
                    'IsDirectory': record.is_directory,
                    'FileName': record.filename,
                    'FullPath': record.full_path if include_path else "",
                    'FileAttr': format_file_attr(record.si_flags),
                    'SI_Created': record.si_created,
                    'SI_Modified': record.si_modified,
                    'SI_MFTModified': record.si_mft_modified,
                    'SI_Accessed': record.si_accessed,
                    'FN_Created': record.fn_created,
                    'FN_Modified': record.fn_modified,
                    'FN_MFTModified': record.fn_mft_modified,
                    'FN_Accessed': record.fn_accessed,
                    'DataSize': record.data_size,
                    'IsResident': record.is_resident
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
            CREATE TABLE IF NOT EXISTS mft (
                EntryNumber INTEGER PRIMARY KEY,
                SequenceNumber INTEGER,
                InUse INTEGER,
                IsDirectory INTEGER,
                FileName TEXT,
                FullPath TEXT,
                FileAttr TEXT,
                SI_Created TEXT,
                SI_Modified TEXT,
                SI_MFTModified TEXT,
                SI_Accessed TEXT,
                FN_Created TEXT,
                FN_Modified TEXT,
                FN_MFTModified TEXT,
                FN_Accessed TEXT,
                DataSize INTEGER,
                IsResident INTEGER
            )
        ''')

        if include_path:
            entries = parser.iter_entries_with_paths(include_deleted)
        else:
            entries = parser.iter_entries(include_deleted)

        batch = []
        for record in entries:
            batch.append((
                record.entry_number,
                record.sequence_number,
                1 if record.in_use else 0,
                1 if record.is_directory else 0,
                record.filename,
                record.full_path if include_path else "",
                format_file_attr(record.si_flags),
                record.si_created,
                record.si_modified,
                record.si_mft_modified,
                record.si_accessed,
                record.fn_created,
                record.fn_modified,
                record.fn_mft_modified,
                record.fn_accessed,
                record.data_size,
                1 if record.is_resident else 0
            ))

            if len(batch) >= 10000:
                cursor.executemany('''
                    INSERT OR REPLACE INTO mft VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ''', batch)
                conn.commit()
                batch = []

        if batch:
            cursor.executemany('''
                INSERT OR REPLACE INTO mft VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ''', batch)
            conn.commit()

        # 인덱스 생성
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_filename ON mft(FileName)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_fullpath ON mft(FullPath)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_si_modified ON mft(SI_Modified)')
        conn.commit()
        conn.close()
