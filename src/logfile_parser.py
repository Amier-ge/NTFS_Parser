"""$LogFile 파서 모듈 - NTFS 트랜잭션 로그 분석"""

import struct
from typing import Generator, Optional
from pathlib import Path
from dataclasses import dataclass

from .constants import (
    filetime_to_datetime, format_timestamp, format_file_attr,
    format_file_reference
)


# Redo/Undo Operation 코드
OPCODE_NAMES = {
    0x00: "Noop",
    0x01: "CompensationLogRecord",
    0x02: "InitializeFileRecordSegment",
    0x03: "DeallocateFileRecordSegment",
    0x04: "WriteEndOfFileRecordSegment",
    0x05: "CreateAttribute",
    0x06: "DeleteAttribute",
    0x07: "UpdateResidentValue",
    0x08: "UpdateNonresidentValue",
    0x09: "UpdateMappingPairs",
    0x0A: "DeleteDirtyClusters",
    0x0B: "SetNewAttributeSizes",
    0x0C: "AddIndexEntryRoot",
    0x0D: "DeleteIndexEntryRoot",
    0x0E: "AddIndexEntryAllocation",
    0x0F: "UpdateFileNameRoot",
    0x10: "UpdateFileNameAllocation",
    0x11: "SetIndexEntryVcnAllocation",
    0x12: "DeleteIndexEntryAllocation",
    0x13: "SetBitsInNonresidentBitMap",
    0x14: "ClearBitsInNonresidentBitMap",
    0x15: "SetBitsInNonresidentBitMap2",
    0x19: "PrepareTransaction",
    0x1A: "CommitTransaction",
    0x1B: "ForgetTransaction",
    0x1C: "OpenNonresidentAttribute",
    0x1F: "DirtyPageTableDump",
    0x20: "TransactionTableDump",
    0x21: "UpdateRecordDataRoot",
}


@dataclass
class LogRecord:
    """로그 레코드"""
    # Record Header (0x58 bytes)
    this_lsn: int = 0              # 0x00-0x07: This LSN
    previous_lsn: int = 0          # 0x08-0x0F: Previous LSN
    client_undo_lsn: int = 0       # 0x10-0x17: Client Undo LSN
    client_data_length: int = 0    # 0x18-0x1B: Client Data Length
    client_id: int = 0             # 0x1C-0x1F: Client ID
    record_type: int = 0           # 0x20-0x23: Record Type
    transaction_id: int = 0        # 0x24-0x27: Transaction ID
    flags: int = 0                 # 0x28-0x29: Flags
    # 0x2A-0x2F: Reserved
    redo_op: int = 0               # 0x30-0x31: Redo Op
    undo_op: int = 0               # 0x32-0x33: Undo Op
    redo_offset: int = 0           # 0x34-0x35: Redo Offset
    redo_length: int = 0           # 0x36-0x37: Redo Length
    undo_offset: int = 0           # 0x38-0x39: Undo Offset
    undo_length: int = 0           # 0x3A-0x3B: Undo Length
    target_attribute: int = 0      # 0x3C-0x3D: Target Attribute
    lcns_to_follow: int = 0        # 0x3E-0x3F: LCN to Follow
    record_offset: int = 0         # 0x40-0x41: Record Offset
    attribute_offset: int = 0      # 0x42-0x43: Attribute Offset
    # 0x44-0x47: Reserved
    target_vcn: int = 0            # 0x48-0x4F: Target VCN
    target_lcn: int = 0            # 0x50-0x53: Target LCN
    # 0x54-0x57: Reserved

    # 파싱된 데이터
    filename: str = ""
    file_reference: int = 0
    parent_reference: int = 0
    timestamp: str = ""
    event: str = ""
    file_attr: int = 0

    # 호환성을 위한 별칭
    @property
    def lsn(self):
        return self.this_lsn


class RestartPage:
    """
    $LogFile Restart 페이지 (RSTR)

    Restart Page Header 구조:
    0x00-0x03: Magic Number ('RSTR')
    0x04-0x05: Update Sequence Offset
    0x06-0x07: Update Sequence Count
    0x08-0x0F: Check Disk LSN
    0x10-0x13: System Page Size
    0x14-0x17: Log Page Size
    0x18-0x19: Restart Offset
    0x1A-0x1B: Minor Version
    0x1C-0x1D: Major Version
    0x1E-0x1F: (padding)
    0x20-0x2F: Update Sequence Array
    0x30-0x37: Current LSN
    0x38-0x39: Log Client
    0x3A-0x3B: Client List
    0x3C-0x3D: Flags
    """

    def __init__(self, data: bytes):
        self.data = data
        self.is_valid = False
        self.system_page_size = 4096
        self.log_page_size = 4096
        self.restart_offset = 0
        self.major_version = 0
        self.minor_version = 0
        self.current_lsn = 0
        self.log_clients = 0

    def parse(self) -> bool:
        """Restart 페이지 파싱"""
        if len(self.data) < 0x40:
            return False

        # 시그니처 확인 (0x00-0x03)
        if self.data[0:4] != b'RSTR':
            return False

        try:
            # Fixup 적용
            fixup_offset = struct.unpack('<H', self.data[0x04:0x06])[0]
            fixup_count = struct.unpack('<H', self.data[0x06:0x08])[0]

            if fixup_count > 1 and fixup_offset > 0:
                self._apply_fixup(fixup_offset, fixup_count)

            # System Page Size (0x10-0x13)
            self.system_page_size = struct.unpack('<I', self.data[0x10:0x14])[0]

            # Log Page Size (0x14-0x17)
            self.log_page_size = struct.unpack('<I', self.data[0x14:0x18])[0]

            # Restart Offset (0x18-0x19)
            self.restart_offset = struct.unpack('<H', self.data[0x18:0x1A])[0]

            # Minor Version (0x1A-0x1B)
            self.minor_version = struct.unpack('<H', self.data[0x1A:0x1C])[0]

            # Major Version (0x1C-0x1D)
            self.major_version = struct.unpack('<H', self.data[0x1C:0x1E])[0]

            # Current LSN (0x30-0x37)
            self.current_lsn = struct.unpack('<Q', self.data[0x30:0x38])[0]

            # Log Client (0x38-0x39)
            self.log_clients = struct.unpack('<H', self.data[0x38:0x3A])[0]

            self.is_valid = True
            return True

        except struct.error:
            return False

    def _apply_fixup(self, offset: int, count: int):
        """Fixup 배열 적용"""
        if offset + count * 2 > len(self.data):
            return

        data = bytearray(self.data)

        for i in range(1, count):
            fixup_value = data[offset + i * 2:offset + i * 2 + 2]
            sector_end = (i * 512) - 2

            if sector_end + 2 <= len(data):
                data[sector_end:sector_end + 2] = fixup_value

        self.data = bytes(data)


class RecordPage:
    """
    $LogFile Record 페이지 (RCRD)

    Common Page Header 구조:
    0x00-0x03: Magic Number ('RCRD')
    0x04-0x05: Update Sequence Offset
    0x06-0x07: Update Sequence Count
    0x08-0x0F: Last LSN
    0x10-0x13: Flags
    0x14-0x15: Page Count
    0x16-0x17: Page Position
    0x18-0x19: Next Record Offset
    0x1A-0x1B: Word Align
    0x1C-0x1F: Dword Align
    0x20-0x27: Last End LSN
    0x28-0x2F: Reserved
    """

    HEADER_SIZE = 0x30  # 48 bytes

    def __init__(self, data: bytes, page_offset: int):
        self.data = data
        self.page_offset = page_offset
        self.is_valid = False
        self.last_lsn = 0
        self.flags = 0
        self.page_count = 0
        self.page_position = 0
        self.next_record_offset = 0
        self.last_end_lsn = 0

    def parse(self) -> bool:
        if len(self.data) < self.HEADER_SIZE:
            return False

        # 시그니처 확인 (0x00-0x03)
        if self.data[0:4] != b'RCRD':
            return False

        try:
            # Fixup 처리
            fixup_offset = struct.unpack('<H', self.data[0x04:0x06])[0]
            fixup_count = struct.unpack('<H', self.data[0x06:0x08])[0]

            if fixup_count > 1 and fixup_offset > 0:
                self._apply_fixup(fixup_offset, fixup_count)

            # Last LSN (0x08-0x0F)
            self.last_lsn = struct.unpack('<Q', self.data[0x08:0x10])[0]

            # Flags (0x10-0x13)
            self.flags = struct.unpack('<I', self.data[0x10:0x14])[0]

            # Page Count (0x14-0x15)
            self.page_count = struct.unpack('<H', self.data[0x14:0x16])[0]

            # Page Position (0x16-0x17)
            self.page_position = struct.unpack('<H', self.data[0x16:0x18])[0]

            # Next Record Offset (0x18-0x19)
            self.next_record_offset = struct.unpack('<H', self.data[0x18:0x1A])[0]

            # Last End LSN (0x20-0x27)
            self.last_end_lsn = struct.unpack('<Q', self.data[0x20:0x28])[0]

            self.is_valid = True
            return True

        except struct.error:
            return False

    def _apply_fixup(self, offset: int, count: int):
        if offset + count * 2 > len(self.data):
            return

        data = bytearray(self.data)

        for i in range(1, count):
            fixup_value = data[offset + i * 2:offset + i * 2 + 2]
            sector_end = (i * 512) - 2

            if sector_end + 2 <= len(data):
                data[sector_end:sector_end + 2] = fixup_value

        self.data = bytes(data)


class LogFileParser:

    DEFAULT_PAGE_SIZE = 4096
    LOG_RECORD_HEADER_SIZE = 0x58  # 88 bytes

    def __init__(self, logfile_path: str):
        self.logfile_path = Path(logfile_path)
        self.restart_page = None
        self.page_size = self.DEFAULT_PAGE_SIZE
        self.current_lsn = 0

    def parse_restart_area(self) -> bool:
        with open(self.logfile_path, 'rb') as f:
            # 첫 번째 restart page
            data = f.read(self.DEFAULT_PAGE_SIZE)
            self.restart_page = RestartPage(data)

            if not self.restart_page.parse():
                # 두 번째 restart page 시도
                data = f.read(self.DEFAULT_PAGE_SIZE)
                self.restart_page = RestartPage(data)
                if not self.restart_page.parse():
                    return False

            self.page_size = self.restart_page.log_page_size or self.DEFAULT_PAGE_SIZE
            self.current_lsn = self.restart_page.current_lsn
            return True

    def iter_records(self) -> Generator[LogRecord, None, None]:
        if not self.parse_restart_area():
            return

        file_size = self.logfile_path.stat().st_size

        with open(self.logfile_path, 'rb') as f:
            # Restart 페이지 2개 이후부터 시작 (보통 0x2000부터)
            page_offset = self.page_size * 2

            while page_offset < file_size:
                f.seek(page_offset)
                page_data = f.read(self.page_size)

                if len(page_data) < self.page_size:
                    break

                # 빈 페이지 스킵
                if page_data[:4] == b'\x00\x00\x00\x00':
                    page_offset += self.page_size
                    continue

                page = RecordPage(page_data, page_offset)
                if page.parse():
                    # 페이지 내 레코드 파싱
                    for record in self._parse_page_records(page):
                        yield record

                page_offset += self.page_size

    def _parse_page_records(self, page: RecordPage) -> Generator[LogRecord, None, None]:
        data = page.data
        offset = RecordPage.HEADER_SIZE  # 0x30부터 시작

        while offset + self.LOG_RECORD_HEADER_SIZE <= len(data):
            # LSN이 0이면 빈 공간
            if data[offset:offset + 8] == b'\x00\x00\x00\x00\x00\x00\x00\x00':
                break

            record = self._parse_log_record(data, offset)
            if record:
                yield record

                # 다음 레코드로 이동 (헤더 + 클라이언트 데이터, 8바이트 정렬)
                record_size = self.LOG_RECORD_HEADER_SIZE + record.client_data_length
                record_size = (record_size + 7) & ~7
                offset += record_size
            else:
                # 파싱 실패시 다음 8바이트 정렬 위치로
                offset += 8

    def _parse_log_record(self, data: bytes, offset: int) -> Optional[LogRecord]:
        """
        개별 로그 레코드 파싱

        Log Record Header 구조 (0x58 bytes):
        0x00-0x07: This LSN
        0x08-0x0F: Previous LSN
        0x10-0x17: Client Undo LSN
        0x18-0x1B: Client Data Length
        0x1C-0x1F: Client ID
        0x20-0x23: Record Type
        0x24-0x27: Transaction ID
        0x28-0x29: Flags
        0x2A-0x2F: Reserved
        0x30-0x31: Redo Op
        0x32-0x33: Undo Op
        0x34-0x35: Redo Offset
        0x36-0x37: Redo Length
        0x38-0x39: Undo Offset
        0x3A-0x3B: Undo Length
        0x3C-0x3D: Target Attribute
        0x3E-0x3F: LCN to Follow
        0x40-0x41: Record Offset
        0x42-0x43: Attribute Offset
        0x44-0x47: Reserved
        0x48-0x4F: Target VCN
        0x50-0x53: Target LCN
        0x54-0x57: Reserved
        """
        if offset + self.LOG_RECORD_HEADER_SIZE > len(data):
            return None

        record = LogRecord()
        try:
            # This LSN (0x00-0x07)
            record.this_lsn = struct.unpack('<Q', data[offset + 0x00:offset + 0x08])[0]
            if record.this_lsn == 0:
                return None

            # Previous LSN (0x08-0x0F)
            record.previous_lsn = struct.unpack('<Q', data[offset + 0x08:offset + 0x10])[0]

            # Client Undo LSN (0x10-0x17)
            record.client_undo_lsn = struct.unpack('<Q', data[offset + 0x10:offset + 0x18])[0]

            # Client Data Length (0x18-0x1B)
            record.client_data_length = struct.unpack('<I', data[offset + 0x18:offset + 0x1C])[0]

            # 유효성 검사
            if record.client_data_length > 0x10000:
                return None

            # Client ID (0x1C-0x1F)
            record.client_id = struct.unpack('<I', data[offset + 0x1C:offset + 0x20])[0]

            # Record Type (0x20-0x23)
            record.record_type = struct.unpack('<I', data[offset + 0x20:offset + 0x24])[0]

            # Transaction ID (0x24-0x27)
            record.transaction_id = struct.unpack('<I', data[offset + 0x24:offset + 0x28])[0]

            # Flags (0x28-0x29)
            record.flags = struct.unpack('<H', data[offset + 0x28:offset + 0x2A])[0]

            # Redo Op (0x30-0x31)
            record.redo_op = struct.unpack('<H', data[offset + 0x30:offset + 0x32])[0]

            # Undo Op (0x32-0x33)
            record.undo_op = struct.unpack('<H', data[offset + 0x32:offset + 0x34])[0]

            # Redo Offset (0x34-0x35)
            record.redo_offset = struct.unpack('<H', data[offset + 0x34:offset + 0x36])[0]

            # Redo Length (0x36-0x37)
            record.redo_length = struct.unpack('<H', data[offset + 0x36:offset + 0x38])[0]

            # Undo Offset (0x38-0x39)
            record.undo_offset = struct.unpack('<H', data[offset + 0x38:offset + 0x3A])[0]

            # Undo Length (0x3A-0x3B)
            record.undo_length = struct.unpack('<H', data[offset + 0x3A:offset + 0x3C])[0]

            # Target Attribute (0x3C-0x3D)
            record.target_attribute = struct.unpack('<H', data[offset + 0x3C:offset + 0x3E])[0]

            # LCN to Follow (0x3E-0x3F)
            record.lcns_to_follow = struct.unpack('<H', data[offset + 0x3E:offset + 0x40])[0]

            # Record Offset (0x40-0x41)
            record.record_offset = struct.unpack('<H', data[offset + 0x40:offset + 0x42])[0]

            # Attribute Offset (0x42-0x43)
            record.attribute_offset = struct.unpack('<H', data[offset + 0x42:offset + 0x44])[0]

            # Target VCN (0x48-0x4F)
            record.target_vcn = struct.unpack('<Q', data[offset + 0x48:offset + 0x50])[0]

            # Target LCN (0x50-0x53) - 4바이트
            record.target_lcn = struct.unpack('<I', data[offset + 0x50:offset + 0x54])[0]

            # 이벤트 타입
            record.event = OPCODE_NAMES.get(record.redo_op, f"Op0x{record.redo_op:02X}")

            # 클라이언트 데이터 파싱
            client_offset = offset + self.LOG_RECORD_HEADER_SIZE
            if record.client_data_length > 0 and client_offset + record.client_data_length <= len(data):
                client_data = data[client_offset:client_offset + record.client_data_length]
                self._parse_client_data(record, client_data)

        except struct.error:
            return None

        return record

    def _parse_client_data(self, record: LogRecord, data: bytes):
        if len(data) == 0:
            return
        
        filename_ops = [0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x12]

        if record.redo_op in filename_ops:
            # Redo 데이터에서 파일명 추출 시도
            if record.redo_length > 0 and record.redo_offset + record.redo_length <= len(data):
                redo_data = data[record.redo_offset:record.redo_offset + record.redo_length]
                self._extract_filename_from_index_entry(record, redo_data)

            # 실패시 전체 데이터에서 시도
            if not record.filename:
                self._extract_filename_from_index_entry(record, data)

        # Undo에서도 시도
        if not record.filename and record.undo_op in filename_ops:
            if record.undo_length > 0 and record.undo_offset + record.undo_length <= len(data):
                undo_data = data[record.undo_offset:record.undo_offset + record.undo_length]
                self._extract_filename_from_index_entry(record, undo_data)

        # InitializeFileRecordSegment (0x02) - MFT 레코드 생성
        if not record.filename and record.redo_op == 0x02:
            if record.redo_length > 0 and record.redo_offset + record.redo_length <= len(data):
                redo_data = data[record.redo_offset:record.redo_offset + record.redo_length]
                self._scan_for_filename(record, redo_data)
            if not record.filename:
                self._scan_for_filename(record, data)

        # CreateAttribute (0x05), DeleteAttribute (0x06)
        if not record.filename and record.redo_op in [0x05, 0x06]:
            if record.redo_length > 0 and record.redo_offset + record.redo_length <= len(data):
                redo_data = data[record.redo_offset:record.redo_offset + record.redo_length]
                self._parse_attribute_for_filename(record, redo_data)
            if not record.filename:
                self._parse_attribute_for_filename(record, data)

        # 여전히 못 찾았으면 전체 스캔
        if not record.filename and len(data) >= 0x44:
            self._scan_for_filename(record, data)

    def _extract_filename_from_index_entry(self, record: LogRecord, data: bytes):
        """
        인덱스 엔트리에서 파일명 추출

        Index Entry 구조 ($I30):
        0x00-0x07: File Reference (MFT entry of the file)
        0x08-0x09: Index Entry Length
        0x0A-0x0B: File Name Attribute Length
        0x0C-0x0F: Flags
        0x10~: $FILE_NAME Attribute Content

        $FILE_NAME Attribute Content:
        0x00-0x07: Parent Directory Reference
        0x08-0x0F: Creation Time
        0x10-0x17: Modification Time
        0x18-0x1F: MFT Modification Time
        0x20-0x27: Last Access Time
        0x28-0x2F: Allocated Size
        0x30-0x37: Real Size
        0x38-0x3B: Flags
        0x3C-0x3F: Reparse Value
        0x40: Filename Length (in characters)
        0x41: Filename Namespace
        0x42~: Filename (UTF-16LE)
        """
        if len(data) < 0x52:  # 최소 크기
            self._parse_filename_attribute(record, data, 0)
            return

        try:
            # 인덱스 엔트리 헤더
            file_ref = struct.unpack('<Q', data[0x00:0x08])[0]
            entry_len = struct.unpack('<H', data[0x08:0x0A])[0]
            filename_attr_len = struct.unpack('<H', data[0x0A:0x0C])[0]

            # 유효성 검사
            file_entry = file_ref & 0x0000FFFFFFFFFFFF
            if file_entry < 0x1000000000 and entry_len > 0x10 and filename_attr_len > 0:
                record.file_reference = file_ref
                # $FILE_NAME 속성은 0x10부터 시작
                if len(data) >= 0x10 + 0x44:
                    self._parse_filename_attribute(record, data, 0x10)
                    if record.filename:
                        return

            # 인덱스 엔트리가 아닐 수 있음, 직접 파싱 시도
            self._parse_filename_attribute(record, data, 0)

        except struct.error:
            self._parse_filename_attribute(record, data, 0)

    def _parse_filename_attribute(self, record: LogRecord, data: bytes, offset: int):
        """
        $FILE_NAME 속성에서 파일명 추출

        $FILE_NAME 구조:
        0x00-0x07: Parent Directory Reference
        0x08-0x0F: Creation Time
        0x10-0x17: Modification Time
        0x18-0x1F: MFT Modification Time
        0x20-0x27: Last Access Time
        0x28-0x2F: Allocated Size
        0x30-0x37: Real Size
        0x38-0x3B: Flags
        0x3C-0x3F: Reparse Value
        0x40: Filename Length (in characters)
        0x41: Filename Namespace (0=POSIX, 1=Win32, 2=DOS, 3=Win32+DOS)
        0x42~: Filename (UTF-16LE)
        """
        if offset + 0x44 > len(data):
            return

        try:
            name_len = data[offset + 0x40]
            namespace = data[offset + 0x41]

            # 유효성 검사
            if name_len < 1 or name_len > 255 or namespace > 3:
                return

            name_end = offset + 0x42 + (name_len * 2)
            if name_end > len(data):
                return

            # 파일명 추출
            filename = data[offset + 0x42:name_end].decode('utf-16-le', errors='ignore')

            # 유효한 파일명인지 확인
            if not filename:
                return

            # 출력 불가능한 문자 체크
            if not all(c.isprintable() or c in ' .\t' for c in filename):
                return

            record.filename = filename

            # 부모 참조 (0x00-0x07)
            record.parent_reference = struct.unpack('<Q', data[offset + 0x00:offset + 0x08])[0]

            # 타임스탬프 - Creation Time (0x08-0x0F)
            creation_time = struct.unpack('<Q', data[offset + 0x08:offset + 0x10])[0]
            if creation_time > 0:
                dt = filetime_to_datetime(creation_time)
                if dt:
                    record.timestamp = format_timestamp(dt)

            # 파일 속성 (0x38-0x3B)
            record.file_attr = struct.unpack('<I', data[offset + 0x38:offset + 0x3C])[0]

        except (struct.error, UnicodeDecodeError):
            pass

    def _parse_attribute_for_filename(self, record: LogRecord, data: bytes):
        if len(data) < 0x18:
            return

        try:
            # 속성 타입 확인 (0x30 = $FILE_NAME)
            attr_type = struct.unpack('<I', data[0:4])[0]

            if attr_type == 0x30:
                # Resident 속성 헤더 건너뛰기 (보통 0x18)
                attr_length = struct.unpack('<I', data[4:8])[0]
                if attr_length > 0x18 and len(data) > 0x18:
                    self._parse_filename_attribute(record, data, 0x18)
            else:
                # 타입이 다르면 스캔
                self._scan_for_filename(record, data)

        except struct.error:
            self._scan_for_filename(record, data)

    def _scan_for_filename(self, record: LogRecord, data: bytes):
        if len(data) < 0x44:
            return

        # 8바이트 정렬 위치에서 검색
        for offset in range(0, len(data) - 0x44, 8):
            try:
                name_len = data[offset + 0x40]
                namespace = data[offset + 0x41]

                # 유효한 FILE_NAME 구조인지 확인
                if 1 <= name_len <= 255 and namespace <= 3:
                    name_end = offset + 0x42 + (name_len * 2)
                    if name_end <= len(data):
                        filename = data[offset + 0x42:name_end].decode('utf-16-le', errors='ignore')

                        if filename and len(filename) >= 1:
                            # 출력 가능한 문자인지 확인
                            if all(c.isprintable() or c in ' .\t' for c in filename):
                                # 부모 참조 유효성 검사
                                parent_ref = struct.unpack('<Q', data[offset:offset + 8])[0]
                                parent_entry = parent_ref & 0x0000FFFFFFFFFFFF

                                if parent_entry < 0x1000000000:
                                    record.filename = filename
                                    record.parent_reference = parent_ref

                                    # 타임스탬프
                                    ts = struct.unpack('<Q', data[offset + 0x08:offset + 0x10])[0]
                                    if ts > 0:
                                        dt = filetime_to_datetime(ts)
                                        if dt:
                                            record.timestamp = format_timestamp(dt)

                                    # 파일 속성
                                    record.file_attr = struct.unpack('<I', data[offset + 0x38:offset + 0x3C])[0]
                                    return

            except (struct.error, UnicodeDecodeError):
                continue


def parse_logfile(logfile_path: str, output_path: str, output_format: str = 'csv'):
    import csv
    import json

    parser = LogFileParser(logfile_path)

    headers = [
        'LSN', 'Timestamp', 'FileName', 'Event', 'FileAttr',
        'FileReferenceNumber', 'ParentFileReferenceNumber',
        'TransactionID', 'RedoOp', 'UndoOp', 'TargetAttribute'
    ]

    if output_format == 'csv':
        with open(output_path, 'w', newline='', encoding='utf-8-sig') as f:
            writer = csv.writer(f)
            writer.writerow(headers)

            for record in parser.iter_records():
                row = [
                    record.this_lsn,
                    record.timestamp,
                    record.filename,
                    record.event,
                    format_file_attr(record.file_attr),
                    format_file_reference(record.file_reference) if record.file_reference else "",
                    format_file_reference(record.parent_reference) if record.parent_reference else "",
                    record.transaction_id,
                    OPCODE_NAMES.get(record.redo_op, f"0x{record.redo_op:02X}"),
                    OPCODE_NAMES.get(record.undo_op, f"0x{record.undo_op:02X}"),
                    record.target_attribute
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

                obj = {
                    'LSN': record.this_lsn,
                    'Timestamp': record.timestamp,
                    'FileName': record.filename,
                    'Event': record.event,
                    'FileAttr': format_file_attr(record.file_attr),
                    'FileReferenceNumber': format_file_reference(record.file_reference) if record.file_reference else "",
                    'ParentFileReferenceNumber': format_file_reference(record.parent_reference) if record.parent_reference else "",
                    'TransactionID': record.transaction_id,
                    'RedoOp': OPCODE_NAMES.get(record.redo_op, f"0x{record.redo_op:02X}"),
                    'UndoOp': OPCODE_NAMES.get(record.undo_op, f"0x{record.undo_op:02X}"),
                    'TargetAttribute': record.target_attribute
                }
                f.write('  ' + json.dumps(obj, ensure_ascii=False))

            f.write('\n]')
