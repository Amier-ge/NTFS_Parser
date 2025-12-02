import os
import csv
import json
import sqlite3
from typing import Generator, List, Dict, Optional
from pathlib import Path
from dataclasses import dataclass, asdict
from datetime import datetime

from .constants import format_timestamp, KST


@dataclass
class UnifiedRecord:
    timestamp: str = ""
    source: str = ""  # MFT, LogFile, UsnJrnl
    event: str = ""
    filename: str = ""
    full_path: str = ""
    file_attr: str = ""
    file_reference: str = ""
    parent_reference: str = ""
    extra_info: str = ""


class UnifiedAnalyzer:

    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def analyze_all(self, mft_path: str = None, logfile_path: str = None,
                    usnjrnl_path: str = None, output_format: str = 'csv') -> str:

        results_file = self.output_dir / f"unified_timeline.{output_format}"

        if output_format == 'csv':
            return self._write_csv(results_file, mft_path, logfile_path, usnjrnl_path)
        elif output_format == 'json':
            return self._write_json(results_file, mft_path, logfile_path, usnjrnl_path)
        elif output_format == 'sqlite':
            return self._write_sqlite(results_file, mft_path, logfile_path, usnjrnl_path)
        else:
            raise ValueError(f"Unsupported format: {output_format}")

    def _iter_all_records(self, mft_path: str = None, logfile_path: str = None,
                          usnjrnl_path: str = None) -> Generator[UnifiedRecord, None, None]:

        # MFT 레코드
        if mft_path and Path(mft_path).exists():
            from .mft_parser import MFTParser
            parser = MFTParser(mft_path)

            for record in parser.iter_entries_with_paths():
                if record.si_created:
                    yield UnifiedRecord(
                        timestamp=record.si_created,
                        source="MFT",
                        event="FileCreate (SI)",
                        filename=record.filename,
                        full_path=record.full_path,
                        file_attr=record.si_flags,
                        file_reference=f"{record.entry_number}-{record.sequence_number}",
                        parent_reference=str(record.parent_ref)
                    )

                if record.si_modified and record.si_modified != record.si_created:
                    yield UnifiedRecord(
                        timestamp=record.si_modified,
                        source="MFT",
                        event="FileModify (SI)",
                        filename=record.filename,
                        full_path=record.full_path,
                        file_attr=record.si_flags,
                        file_reference=f"{record.entry_number}-{record.sequence_number}",
                        parent_reference=str(record.parent_ref)
                    )

        # UsnJrnl 레코드
        if usnjrnl_path and Path(usnjrnl_path).exists():
            from .usnjrnl_parser import UsnJrnlParserWithMFT, UsnJrnlParser

            if mft_path:
                parser = UsnJrnlParserWithMFT(usnjrnl_path, mft_path)
                parser.build_path_cache_from_mft()
            else:
                parser = UsnJrnlParser(usnjrnl_path)

            for record in parser.iter_records():
                full_path = ""
                if mft_path and hasattr(parser, 'get_full_path'):
                    full_path = parser.get_full_path(record.file_reference)

                yield UnifiedRecord(
                    timestamp=record.timestamp,
                    source="UsnJrnl",
                    event=record.event,
                    filename=record.filename,
                    full_path=full_path,
                    file_attr=record.file_attr_str,
                    file_reference=record.file_ref_str,
                    parent_reference=record.parent_ref_str,
                    extra_info=f"USN:{record.usn}"
                )

        # LogFile 레코드
        if logfile_path and Path(logfile_path).exists():
            from .logfile_parser import LogFileParser

            parser = LogFileParser(logfile_path)
            for record in parser.iter_records():
                if record.filename or record.event:
                    yield UnifiedRecord(
                        timestamp=record.timestamp,
                        source="LogFile",
                        event=record.event,
                        filename=record.filename,
                        full_path="",
                        file_attr="",
                        file_reference=str(record.file_reference) if record.file_reference else "",
                        parent_reference=str(record.parent_reference) if record.parent_reference else "",
                        extra_info=f"LSN:{record.lsn}"
                    )

    def _write_csv(self, output_path: Path, mft_path: str, logfile_path: str,
                   usnjrnl_path: str) -> str:

        headers = [
            'Timestamp', 'Source', 'Event', 'FileName', 'FullPath',
            'FileAttr', 'FileReferenceNumber', 'ParentFileReferenceNumber', 'ExtraInfo'
        ]

        with open(output_path, 'w', newline='', encoding='utf-8-sig') as f:
            writer = csv.writer(f)
            writer.writerow(headers)

            for record in self._iter_all_records(mft_path, logfile_path, usnjrnl_path):
                writer.writerow([
                    record.timestamp,
                    record.source,
                    record.event,
                    record.filename,
                    record.full_path,
                    record.file_attr,
                    record.file_reference,
                    record.parent_reference,
                    record.extra_info
                ])

        return str(output_path)

    def _write_json(self, output_path: Path, mft_path: str, logfile_path: str,
                    usnjrnl_path: str) -> str:

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write('[\n')
            first = True

            for record in self._iter_all_records(mft_path, logfile_path, usnjrnl_path):
                if not first:
                    f.write(',\n')
                first = False

                f.write('  ' + json.dumps(asdict(record), ensure_ascii=False))

            f.write('\n]')

        return str(output_path)

    def _write_sqlite(self, output_path: Path, mft_path: str, logfile_path: str,
                      usnjrnl_path: str) -> str:

        db_path = output_path.with_suffix('.db')

        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()

        # 테이블 생성
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS timeline (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                source TEXT,
                event TEXT,
                filename TEXT,
                full_path TEXT,
                file_attr TEXT,
                file_reference TEXT,
                parent_reference TEXT,
                extra_info TEXT
            )
        ''')

        cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON timeline(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_filename ON timeline(filename)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_source ON timeline(source)')

        # 데이터 삽입
        batch = []
        batch_size = 10000

        for record in self._iter_all_records(mft_path, logfile_path, usnjrnl_path):
            batch.append((
                record.timestamp,
                record.source,
                record.event,
                record.filename,
                record.full_path,
                record.file_attr,
                record.file_reference,
                record.parent_reference,
                record.extra_info
            ))

            if len(batch) >= batch_size:
                cursor.executemany('''
                    INSERT INTO timeline (timestamp, source, event, filename, full_path,
                                         file_attr, file_reference, parent_reference, extra_info)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', batch)
                batch = []

        if batch:
            cursor.executemany('''
                INSERT INTO timeline (timestamp, source, event, filename, full_path,
                                     file_attr, file_reference, parent_reference, extra_info)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', batch)

        conn.commit()
        conn.close()

        return str(db_path)


class TimelineBuilder:

    def __init__(self):
        self.events = []

    def add_mft_events(self, mft_path: str):
        """MFT에서 이벤트 추가"""
        from .mft_parser import MFTParser

        parser = MFTParser(mft_path)
        for record in parser.iter_entries_with_paths():
            if record.si_created:
                self.events.append({
                    'timestamp': record.si_created,
                    'source': 'MFT',
                    'event': 'Created',
                    'filename': record.filename,
                    'path': record.full_path
                })

    def add_usnjrnl_events(self, usnjrnl_path: str):
        from .usnjrnl_parser import UsnJrnlParser

        parser = UsnJrnlParser(usnjrnl_path)
        for record in parser.iter_records():
            self.events.append({
                'timestamp': record.timestamp,
                'source': 'UsnJrnl',
                'event': record.event,
                'filename': record.filename,
                'path': ''
            })

    def get_sorted_timeline(self) -> List[Dict]:
        return sorted(self.events, key=lambda x: x.get('timestamp', ''))

    def export_timeline(self, output_path: str, format: str = 'csv'):
        timeline = self.get_sorted_timeline()

        if format == 'csv':
            with open(output_path, 'w', newline='', encoding='utf-8-sig') as f:
                if timeline:
                    writer = csv.DictWriter(f, fieldnames=timeline[0].keys())
                    writer.writeheader()
                    writer.writerows(timeline)
        elif format == 'json':
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(timeline, f, ensure_ascii=False, indent=2)
