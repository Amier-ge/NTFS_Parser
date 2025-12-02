import os
import struct
from typing import Optional, Generator, BinaryIO
from pathlib import Path


class ImageHandler:

    def __init__(self, image_path: str):
        self.image_path = Path(image_path)
        self.image_type = self._detect_image_type()
        self._handle = None
        self._ewf_handle = None
        self._size = 0

    def _detect_image_type(self) -> str:
        ext = self.image_path.suffix.lower()
        if ext in ['.e01', '.ex01', '.s01']:
            return 'ewf'
        elif ext in ['.dd', '.raw', '.img', '.001']:
            return 'raw'
        else:
            # 시그니처로 판단
            with open(self.image_path, 'rb') as f:
                sig = f.read(8)
                if sig[:3] == b'EVF':
                    return 'ewf'
            return 'raw'

    def open(self):
        if self.image_type == 'ewf':
            self._open_ewf()
        else:
            self._open_raw()

    def _open_raw(self):
        self._handle = open(self.image_path, 'rb')
        self._handle.seek(0, 2)
        self._size = self._handle.tell()
        self._handle.seek(0)

    def _open_ewf(self):
        try:
            import pyewf
            filenames = pyewf.glob(str(self.image_path))
            self._ewf_handle = pyewf.handle()
            self._ewf_handle.open(filenames)
            self._size = self._ewf_handle.get_media_size()
        except ImportError:
            raise ImportError("E01 이미지 지원을 위해 pyewf 설치 필요: pip install pyewf-python")

    def close(self):
        if self._handle:
            self._handle.close()
            self._handle = None
        if self._ewf_handle:
            self._ewf_handle.close()
            self._ewf_handle = None

    def read(self, offset: int, size: int) -> bytes:
        if self._ewf_handle:
            self._ewf_handle.seek(offset)
            return self._ewf_handle.read(size)
        else:
            self._handle.seek(offset)
            return self._handle.read(size)

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    @property
    def size(self) -> int:
        return self._size


class NTFSPartition:

    def __init__(self, image: ImageHandler, offset: int = 0):
        self.image = image
        self.offset = offset
        self.boot_sector = None
        self.bytes_per_sector = 512
        self.sectors_per_cluster = 8
        self.cluster_size = 4096
        self.mft_offset = 0
        self.mft_entry_size = 1024

    def parse_boot_sector(self) -> bool:
        data = self.image.read(self.offset, 512)

        # NTFS 시그니처 확인
        if data[3:11] != b'NTFS    ':
            return False

        self.bytes_per_sector = struct.unpack('<H', data[0x0B:0x0D])[0]
        self.sectors_per_cluster = data[0x0D]
        self.cluster_size = self.bytes_per_sector * self.sectors_per_cluster

        # MFT 시작 클러스터
        mft_cluster = struct.unpack('<Q', data[0x30:0x38])[0]
        self.mft_offset = self.offset + (mft_cluster * self.cluster_size)

        # MFT 엔트리 크기
        mft_entry_size_raw = struct.unpack('<b', data[0x40:0x41])[0]
        if mft_entry_size_raw > 0:
            self.mft_entry_size = mft_entry_size_raw * self.cluster_size
        else:
            self.mft_entry_size = 1 << (-mft_entry_size_raw)

        return True

    def read_mft_entry(self, entry_number: int) -> bytes:
        offset = self.mft_offset + (entry_number * self.mft_entry_size)
        return self.image.read(offset, self.mft_entry_size)

    def read_cluster(self, cluster_number: int) -> bytes:
        offset = self.offset + (cluster_number * self.cluster_size)
        return self.image.read(offset, self.cluster_size)


def find_ntfs_partitions(image: ImageHandler) -> list:
    partitions = []

    # MBR 파티션 테이블 확인
    mbr = image.read(0, 512)
    if mbr[510:512] != b'\x55\xAA':
        # MBR 없음 - 전체 이미지가 파티션일 수 있음
        partition = NTFSPartition(image, 0)
        if partition.parse_boot_sector():
            partitions.append(partition)
        return partitions

    # MBR 파티션 엔트리 파싱
    for i in range(4):
        entry_offset = 446 + (i * 16)
        entry = mbr[entry_offset:entry_offset + 16]

        partition_type = entry[4]
        if partition_type in [0x07, 0x17, 0x27]:  # NTFS 파티션 타입
            lba_start = struct.unpack('<I', entry[8:12])[0]
            offset = lba_start * 512

            partition = NTFSPartition(image, offset)
            if partition.parse_boot_sector():
                partitions.append(partition)

    # GPT 확인
    gpt_header = image.read(512, 512)
    if gpt_header[:8] == b'EFI PART':
        partition_entry_lba = struct.unpack('<Q', gpt_header[72:80])[0]
        num_entries = struct.unpack('<I', gpt_header[80:84])[0]
        entry_size = struct.unpack('<I', gpt_header[84:88])[0]

        # Microsoft Basic Data GUID
        ntfs_guid = bytes.fromhex('A2A0D0EBE5B9334487C068B6B72699C7')

        for i in range(min(num_entries, 128)):
            entry_offset = partition_entry_lba * 512 + (i * entry_size)
            entry = image.read(entry_offset, entry_size)

            partition_type_guid = entry[0:16]
            if partition_type_guid == ntfs_guid or entry[0:16] != b'\x00' * 16:
                start_lba = struct.unpack('<Q', entry[32:40])[0]
                if start_lba > 0:
                    offset = start_lba * 512
                    partition = NTFSPartition(image, offset)
                    if partition.parse_boot_sector():
                        partitions.append(partition)

    return partitions


class NTFSExtractor:
    SYSTEM_FILES = {
        '$MFT': 0,
        '$MFTMirr': 1,
        '$LogFile': 2,
        '$Volume': 3,
        '$AttrDef': 4,
        '.': 5,  # Root directory
        '$Bitmap': 6,
        '$Boot': 7,
        '$BadClus': 8,
        '$Secure': 9,
        '$UpCase': 10,
        '$Extend': 11,
    }

    def __init__(self, partition: NTFSPartition):
        self.partition = partition
        self.mft_parser = None

    def extract_file_by_entry(self, entry_number: int, output_path: str,
                              stream_name: str = None) -> bool:
        from .mft_parser import MFTEntry

        entry_data = self.partition.read_mft_entry(entry_number)
        entry = MFTEntry(entry_data, entry_number)

        if not entry.parse():
            return False

        # $DATA 속성에서 데이터 추출
        data_attrs = [a for a in entry.attributes if a['type'] == 0x80]

        for data_attr in data_attrs:
            attr_name = data_attr.get('name', '')

            # 스트림 이름 매칭
            if stream_name is not None:
                if attr_name != stream_name:
                    continue
            elif attr_name:  # 기본 스트림이 아니면 스킵
                continue

            with open(output_path, 'wb') as out_file:
                if data_attr.get('non_resident', False):
                    # Non-resident: 데이터 런 파싱하여 추출
                    self._extract_non_resident(data_attr, out_file)
                else:
                    # Resident: 직접 데이터 쓰기
                    out_file.write(data_attr.get('data', b''))
            return True

        return False

    def _extract_non_resident(self, attr: dict, out_file: BinaryIO):
        data_runs = attr.get('data_runs', [])
        real_size = attr.get('real_size', 0)
        written = 0

        for run in data_runs:
            cluster = run['start_cluster']
            length = run['length']

            for i in range(length):
                if written >= real_size:
                    break

                cluster_data = self.partition.read_cluster(cluster + i)
                remaining = real_size - written

                if remaining < len(cluster_data):
                    out_file.write(cluster_data[:remaining])
                    written += remaining
                else:
                    out_file.write(cluster_data)
                    written += len(cluster_data)

    def extract_mft(self, output_path: str) -> bool:
        return self.extract_file_by_entry(0, output_path)

    def extract_logfile(self, output_path: str) -> bool:
        return self.extract_file_by_entry(2, output_path)

    def extract_usnjrnl(self, output_path: str, verbose: bool = False) -> bool:
        from .mft_parser import MFTEntry
        import struct

        # 1단계: $Extend 디렉토리(엔트리 11)의 인덱스에서 $UsnJrnl 찾기
        if verbose:
            print("[DEBUG] Reading $Extend directory (entry 11)")

        extend_data = self.partition.read_mft_entry(11)
        extend_entry = MFTEntry(extend_data, 11)
        if not extend_entry.parse():
            if verbose:
                print("[DEBUG] Failed to parse $Extend entry")
            return False

        # $Extend의 $INDEX_ROOT에서 자식 파일들 찾기
        usnjrnl_entry_num = self._find_file_in_directory(extend_entry, '$UsnJrnl', verbose)

        if usnjrnl_entry_num is None:
            if verbose:
                print("[DEBUG] $UsnJrnl not found in $Extend directory index")
            # 폴백: MFT 전체 스캔
            usnjrnl_entry_num = self._scan_mft_for_usnjrnl(verbose)

        if usnjrnl_entry_num is None:
            if verbose:
                print("[DEBUG] $UsnJrnl not found - USN Journal may be disabled or deleted on this volume")
            return False

        if verbose:
            print(f"[DEBUG] Found $UsnJrnl at entry {usnjrnl_entry_num}")

        # $UsnJrnl 엔트리 읽기
        usnjrnl_data = self.partition.read_mft_entry(usnjrnl_entry_num)
        usnjrnl_entry = MFTEntry(usnjrnl_data, usnjrnl_entry_num)
        if not usnjrnl_entry.parse():
            if verbose:
                print("[DEBUG] Failed to parse $UsnJrnl entry")
            return False

        return self._extract_usnjrnl_j_stream(usnjrnl_entry, usnjrnl_entry_num, output_path, verbose)

    def _find_file_in_directory(self, dir_entry, filename: str, verbose: bool = False) -> int:
        """디렉토리의 $INDEX_ROOT/$INDEX_ALLOCATION에서 파일 찾기"""
        import struct

        # $INDEX_ROOT (0x90) 확인
        for attr in dir_entry.attributes:
            if attr['type'] == 0x90:  # $INDEX_ROOT
                data = attr.get('data', b'')
                if len(data) < 32:
                    continue

                # INDEX_ROOT 헤더 (16바이트) + INDEX_HEADER
                # INDEX_HEADER : entries_offset(4) + total_size(4) + alloc_size(4) + flags(1)
                entries_offset = struct.unpack('<I', data[16:20])[0]
                idx_flags = data[28] if len(data) > 28 else 0

                # INDEX_ENTRY 파싱
                result = self._parse_index_entries(data, 16 + entries_offset, filename, verbose)
                if result is not None:
                    return result

                # INDEX_ALLOCATION이 필요한 경우 (LARGE_INDEX 플래그)
                if idx_flags & 0x01:
                    if verbose:
                        print("[DEBUG] Large index, checking $INDEX_ALLOCATION")
                    result = self._find_in_index_allocation(dir_entry, filename, verbose)
                    if result is not None:
                        return result

        return None

    def _parse_index_entries(self, data: bytes, offset: int, target_name: str, verbose: bool = False) -> int:
        import struct

        while offset + 16 <= len(data):
            # INDEX_ENTRY 구조
            # MFT reference (8) + entry_length (2) + content_length (2) + flags (4)
            if offset + 16 > len(data):
                break

            mft_ref = struct.unpack('<Q', data[offset:offset+8])[0]
            entry_length = struct.unpack('<H', data[offset+8:offset+10])[0]
            content_length = struct.unpack('<H', data[offset+10:offset+12])[0]
            entry_flags = struct.unpack('<I', data[offset+12:offset+16])[0]

            if entry_length == 0:
                break

            # 마지막 엔트리 체크
            if entry_flags & 0x02:  # LAST_ENTRY
                break

            # $FILE_NAME 구조 파싱 (offset+16부터)
            fn_offset = offset + 16
            if fn_offset + 66 <= len(data) and content_length >= 66:
                name_len = data[fn_offset + 64]
                if fn_offset + 66 + name_len * 2 <= len(data):
                    try:
                        name = data[fn_offset + 66:fn_offset + 66 + name_len * 2].decode('utf-16-le')
                        if verbose:
                            print(f"[DEBUG]   Index entry: '{name}' -> MFT {mft_ref & 0x0000FFFFFFFFFFFF}")
                        if name == target_name:
                            return mft_ref & 0x0000FFFFFFFFFFFF
                    except:
                        pass

            offset += entry_length

        return None

    def _find_in_index_allocation(self, dir_entry, filename: str, verbose: bool = False) -> int:
        import struct

        for attr in dir_entry.attributes:
            if attr['type'] == 0xA0 and attr.get('name', '') == '$I30':  # $INDEX_ALLOCATION
                if not attr.get('non_resident', False):
                    continue

                data_runs = attr.get('data_runs', [])
                if not data_runs:
                    continue

                # 각 인덱스 레코드(INDX) 읽기
                for run in data_runs:
                    if run.get('sparse', False):
                        continue

                    cluster = run['start_cluster']
                    for i in range(run['length']):
                        cluster_data = self.partition.read_cluster(cluster + i)

                        # INDX 시그니처 확인
                        if cluster_data[:4] != b'INDX':
                            continue

                        # Fixup 적용
                        cluster_data = self._apply_fixup_to_index(cluster_data)

                        # INDEX_HEADER는 offset 24부터
                        if len(cluster_data) < 40:
                            continue

                        entries_offset = struct.unpack('<I', cluster_data[24:28])[0]
                        result = self._parse_index_entries(cluster_data, 24 + entries_offset, filename, verbose)
                        if result is not None:
                            return result

        return None

    def _apply_fixup_to_index(self, data: bytes) -> bytes:
        import struct

        if len(data) < 48:
            return data

        fixup_offset = struct.unpack('<H', data[4:6])[0]
        fixup_count = struct.unpack('<H', data[6:8])[0]

        if fixup_count == 0 or fixup_offset + fixup_count * 2 > len(data):
            return data

        data = bytearray(data)
        for i in range(1, fixup_count):
            fixup_value = data[fixup_offset + i * 2:fixup_offset + i * 2 + 2]
            sector_end = (i * 512) - 2
            if sector_end + 2 <= len(data):
                data[sector_end:sector_end + 2] = fixup_value

        return bytes(data)

    def _scan_mft_for_usnjrnl(self, verbose: bool = False) -> int:
        from .mft_parser import MFTEntry

        # MFT 크기 확인
        mft_data = self.partition.read_mft_entry(0)
        mft_entry = MFTEntry(mft_data, 0)
        if not mft_entry.parse():
            return None

        for attr in mft_entry.attributes:
            if attr['type'] == 0x80 and attr.get('name', '') == '':
                total_entries = attr.get('real_size', 0) // self.partition.mft_entry_size
                if verbose:
                    print(f"[DEBUG] Fallback: scanning MFT ({total_entries} entries)")

                scan_limit = min(total_entries, 100000)
                for entry_num in range(scan_limit):
                    try:
                        entry_data = self.partition.read_mft_entry(entry_num)
                        entry = MFTEntry(entry_data, entry_num)
                        if entry.parse():
                            for fn_attr in entry.attributes:
                                if fn_attr['type'] == 0x30:
                                    name = fn_attr.get('filename', '')
                                    parent_ref = fn_attr.get('parent_ref', 0)
                                    parent_entry = parent_ref & 0x0000FFFFFFFFFFFF

                                    if name == '$UsnJrnl' and parent_entry == 11:
                                        return entry_num
                    except:
                        continue

        return None

    def _extract_usnjrnl_j_stream(self, entry, entry_num: int, output_path: str, verbose: bool = False) -> bool:
        from .mft_parser import MFTEntry

        # 모든 $J 데이터 런 수집 (여러 MFT 엔트리에 걸쳐 있을 수 있음)
        all_data_runs = []
        real_size = 0

        if verbose:
            print(f"[DEBUG] Extracting $J from entry {entry_num}")
            print(f"[DEBUG] Attributes found: {[hex(a['type']) for a in entry.attributes]}")

        # $ATTRIBUTE_LIST 확인
        attr_list_entries = []
        for attr in entry.attributes:
            if attr['type'] == 0x20:  # $ATTRIBUTE_LIST
                if verbose:
                    print("[DEBUG] Found $ATTRIBUTE_LIST")
                attr_list_entries = self._parse_attribute_list(attr, entry_num)
                break

        if attr_list_entries:
            if verbose:
                print(f"[DEBUG] Attribute list has {len(attr_list_entries)} entries")
                for al in attr_list_entries:
                    print(f"[DEBUG]   Type: {hex(al['type'])}, Name: '{al.get('name', '')}', MFT Ref: {al['mft_reference'] & 0x0000FFFFFFFFFFFF}")

            # Attribute List가 있는 경우: 관련 MFT 엔트리에서 $J 데이터 런 수집
            for al_entry in attr_list_entries:
                if al_entry['type'] == 0x80 and al_entry.get('name', '') == '$J':
                    ref_entry_num = al_entry['mft_reference'] & 0x0000FFFFFFFFFFFF
                    if verbose:
                        print(f"[DEBUG] Reading $J data from MFT entry {ref_entry_num}")
                    try:
                        ref_data = self.partition.read_mft_entry(ref_entry_num)
                        ref_entry = MFTEntry(ref_data, ref_entry_num)
                        if ref_entry.parse():
                            for ref_attr in ref_entry.attributes:
                                if ref_attr['type'] == 0x80 and ref_attr.get('name', '') == '$J':
                                    if ref_attr.get('non_resident', False):
                                        runs = ref_attr.get('data_runs', [])
                                        if runs:
                                            all_data_runs.extend(runs)
                                            if verbose:
                                                print(f"[DEBUG]   Added {len(runs)} data runs")
                                        # real_size는 start_vcn이 0인 속성에서만 가져옴
                                        if ref_attr.get('start_vcn', 0) == 0:
                                            real_size = ref_attr.get('real_size', 0)
                                            if verbose:
                                                print(f"[DEBUG]   Real size: {real_size}")
                    except Exception as e:
                        if verbose:
                            print(f"[DEBUG] Error reading entry {ref_entry_num}: {e}")
                        continue
        else:
            # Attribute List 없음: 현재 엔트리에서 직접 $J 찾기
            if verbose:
                print("[DEBUG] No $ATTRIBUTE_LIST, searching in current entry")
            for attr in entry.attributes:
                if attr['type'] == 0x80:  # $DATA
                    attr_name = attr.get('name', '')
                    if verbose:
                        print(f"[DEBUG] Found $DATA with name: '{attr_name}'")
                    if attr_name == '$J':
                        if attr.get('non_resident', False):
                            all_data_runs = attr.get('data_runs', [])
                            real_size = attr.get('real_size', 0)
                            if verbose:
                                print(f"[DEBUG] $J is non-resident, {len(all_data_runs)} data runs, size: {real_size}")
                        else:
                            # Resident $J (매우 드묾)
                            if verbose:
                                print("[DEBUG] $J is resident")
                            with open(output_path, 'wb') as out_file:
                                out_file.write(attr.get('data', b''))
                            return True
                        break

        if not all_data_runs:
            if verbose:
                print("[DEBUG] No data runs found for $J")
            return False

        if verbose:
            print(f"[DEBUG] Total data runs: {len(all_data_runs)}, real_size: {real_size}")
            # 처음 5개 데이터 런 정보 출력
            for i, run in enumerate(all_data_runs[:5]):
                print(f"[DEBUG]   Run {i}: cluster {run['start_cluster']}, length {run['length']}, sparse: {run.get('sparse', False)}")
            if len(all_data_runs) > 5:
                print(f"[DEBUG]   ... and {len(all_data_runs) - 5} more runs")

        # 데이터 런을 사용하여 $J 추출 (sparse 영역은 0으로 채움)
        with open(output_path, 'wb') as out_file:
            self._extract_from_data_runs(all_data_runs, real_size, out_file, skip_sparse=False)

        if verbose:
            import os
            if os.path.exists(output_path):
                extracted_size = os.path.getsize(output_path)
                print(f"[DEBUG] Extracted file size: {extracted_size}")

        return True

    def _parse_attribute_list(self, attr: dict, base_entry_num: int) -> list:
        entries = []

        if attr.get('non_resident', False):
            # Non-resident attribute list는 드물지만 처리
            return entries

        data = attr.get('data', b'')
        offset = 0

        while offset + 26 <= len(data):
            attr_type = struct.unpack('<I', data[offset:offset+4])[0]
            record_length = struct.unpack('<H', data[offset+4:offset+6])[0]

            if record_length == 0 or offset + record_length > len(data):
                break

            name_length = data[offset+6]
            name_offset = data[offset+7]
            start_vcn = struct.unpack('<Q', data[offset+8:offset+16])[0]
            mft_reference = struct.unpack('<Q', data[offset+16:offset+24])[0]

            # 속성 이름 추출
            attr_name = ''
            if name_length > 0 and offset + name_offset + name_length * 2 <= len(data):
                try:
                    attr_name = data[offset+name_offset:offset+name_offset+name_length*2].decode('utf-16-le')
                except:
                    pass

            entries.append({
                'type': attr_type,
                'name': attr_name,
                'start_vcn': start_vcn,
                'mft_reference': mft_reference
            })

            offset += record_length

        return entries

    def _extract_from_data_runs(self, data_runs: list, real_size: int, out_file, skip_sparse: bool = True):
        written = 0

        for run in data_runs:
            if real_size > 0 and written >= real_size:
                break

            # Sparse run 처리
            if run.get('sparse', False) or run['start_cluster'] == 0:
                sparse_size = run['length'] * self.partition.cluster_size
                if skip_sparse:
                    # Sparse는 건너뜀 (USN Journal의 sparse 영역)
                    written += sparse_size
                else:
                    # 0으로 채움
                    zero_chunk = b'\x00' * self.partition.cluster_size
                    for _ in range(run['length']):
                        if real_size > 0:
                            remaining = real_size - written
                            if remaining <= 0:
                                break
                            if remaining < len(zero_chunk):
                                out_file.write(zero_chunk[:remaining])
                                written += remaining
                            else:
                                out_file.write(zero_chunk)
                                written += len(zero_chunk)
                        else:
                            out_file.write(zero_chunk)
                            written += len(zero_chunk)
                continue

            cluster = run['start_cluster']
            length = run['length']

            for i in range(length):
                if real_size > 0 and written >= real_size:
                    break

                cluster_data = self.partition.read_cluster(cluster + i)

                if real_size > 0:
                    remaining = real_size - written
                    if remaining < len(cluster_data):
                        out_file.write(cluster_data[:remaining])
                        written += remaining
                    else:
                        out_file.write(cluster_data)
                        written += len(cluster_data)
                else:
                    out_file.write(cluster_data)
                    written += len(cluster_data)
