from enum import IntFlag, IntEnum
from datetime import datetime, timedelta, timezone

# 한국 시간대 (UTC+9)
KST = timezone(timedelta(hours=9))

# NTFS 타임스탬프 에포크 (1601-01-01 00:00:00 UTC)
NTFS_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

MFT_ENTRY_SIZE = 1024

MFT_SIGNATURE = b'FILE'
MFT_SIGNATURE_BAD = b'BAAD'

class AttrType(IntEnum):
    STANDARD_INFORMATION = 0x10
    ATTRIBUTE_LIST = 0x20
    FILE_NAME = 0x30
    OBJECT_ID = 0x40
    SECURITY_DESCRIPTOR = 0x50
    VOLUME_NAME = 0x60
    VOLUME_INFORMATION = 0x70
    DATA = 0x80
    INDEX_ROOT = 0x90
    INDEX_ALLOCATION = 0xA0
    BITMAP = 0xB0
    REPARSE_POINT = 0xC0
    EA_INFORMATION = 0xD0
    EA = 0xE0
    LOGGED_UTILITY_STREAM = 0x100
    END = 0xFFFFFFFF


class FileAttrFlags(IntFlag):
    READ_ONLY = 0x0001
    HIDDEN = 0x0002
    SYSTEM = 0x0004
    DIRECTORY = 0x0010
    ARCHIVE = 0x0020
    DEVICE = 0x0040
    NORMAL = 0x0080
    TEMPORARY = 0x0100
    SPARSE_FILE = 0x0200
    REPARSE_POINT = 0x0400
    COMPRESSED = 0x0800
    OFFLINE = 0x1000
    NOT_CONTENT_INDEXED = 0x2000
    ENCRYPTED = 0x4000


class MftRecordFlags(IntFlag):
    IN_USE = 0x0001
    DIRECTORY = 0x0002
    EXTENSION = 0x0004
    SPECIAL_INDEX = 0x0008


class UsnReason(IntFlag):
    DATA_OVERWRITE = 0x00000001
    DATA_EXTEND = 0x00000002
    DATA_TRUNCATION = 0x00000004
    NAMED_DATA_OVERWRITE = 0x00000010
    NAMED_DATA_EXTEND = 0x00000020
    NAMED_DATA_TRUNCATION = 0x00000040
    FILE_CREATE = 0x00000100
    FILE_DELETE = 0x00000200
    EA_CHANGE = 0x00000400
    SECURITY_CHANGE = 0x00000800
    RENAME_OLD_NAME = 0x00001000
    RENAME_NEW_NAME = 0x00002000
    INDEXABLE_CHANGE = 0x00004000
    BASIC_INFO_CHANGE = 0x00008000
    HARD_LINK_CHANGE = 0x00010000
    COMPRESSION_CHANGE = 0x00020000
    ENCRYPTION_CHANGE = 0x00040000
    OBJECT_ID_CHANGE = 0x00080000
    REPARSE_POINT_CHANGE = 0x00100000
    STREAM_CHANGE = 0x00200000
    TRANSACTED_CHANGE = 0x00400000
    INTEGRITY_CHANGE = 0x00800000
    CLOSE = 0x80000000


class FileNamespace(IntEnum):
    POSIX = 0
    WIN32 = 1
    DOS = 2
    WIN32_AND_DOS = 3


def filetime_to_datetime(filetime: int) -> datetime:
    if filetime == 0 or filetime < 0:
        return None
    try:
        # FILETIME은 100나노초 단위
        seconds = filetime / 10_000_000
        dt = NTFS_EPOCH + timedelta(seconds=seconds)
        return dt.astimezone(KST)
    except (OverflowError, OSError, ValueError):
        return None


def format_timestamp(dt: datetime) -> str:
    if dt is None:
        return ""
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def format_file_attr(flags: int) -> str:
    attrs = []
    if flags & FileAttrFlags.READ_ONLY:
        attrs.append("ReadOnly")
    if flags & FileAttrFlags.HIDDEN:
        attrs.append("Hidden")
    if flags & FileAttrFlags.SYSTEM:
        attrs.append("System")
    if flags & FileAttrFlags.DIRECTORY:
        attrs.append("Directory")
    if flags & FileAttrFlags.ARCHIVE:
        attrs.append("Archive")
    if flags & FileAttrFlags.COMPRESSED:
        attrs.append("Compressed")
    if flags & FileAttrFlags.ENCRYPTED:
        attrs.append("Encrypted")
    if flags & FileAttrFlags.SPARSE_FILE:
        attrs.append("Sparse")
    if flags & FileAttrFlags.REPARSE_POINT:
        attrs.append("ReparsePoint")
    return "|".join(attrs) if attrs else "Normal"


def format_usn_reason(reason: int) -> str:
    reasons = []
    if reason & UsnReason.DATA_OVERWRITE:
        reasons.append("DataOverwrite")
    if reason & UsnReason.DATA_EXTEND:
        reasons.append("DataExtend")
    if reason & UsnReason.DATA_TRUNCATION:
        reasons.append("DataTruncation")
    if reason & UsnReason.FILE_CREATE:
        reasons.append("FileCreate")
    if reason & UsnReason.FILE_DELETE:
        reasons.append("FileDelete")
    if reason & UsnReason.RENAME_OLD_NAME:
        reasons.append("RenameOldName")
    if reason & UsnReason.RENAME_NEW_NAME:
        reasons.append("RenameNewName")
    if reason & UsnReason.SECURITY_CHANGE:
        reasons.append("SecurityChange")
    if reason & UsnReason.BASIC_INFO_CHANGE:
        reasons.append("BasicInfoChange")
    if reason & UsnReason.HARD_LINK_CHANGE:
        reasons.append("HardLinkChange")
    if reason & UsnReason.CLOSE:
        reasons.append("Close")
    return "|".join(reasons) if reasons else f"0x{reason:08X}"


def parse_file_reference(ref: int) -> tuple:
    entry_number = ref & 0x0000FFFFFFFFFFFF
    sequence_number = (ref >> 48) & 0xFFFF
    return entry_number, sequence_number


def format_file_reference(ref: int) -> str:
    entry, seq = parse_file_reference(ref)
    return f"{entry}-{seq}"
