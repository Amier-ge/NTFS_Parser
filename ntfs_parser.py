import argparse
import sys
import os
from pathlib import Path
from datetime import datetime

# 패키지 경로 추가
sys.path.insert(0, str(Path(__file__).parent))

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False


VERSION = "1.0.0"
AUTHOR = "amier-ge"


class Colors:
    # 기본 색상
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    # 스타일
    BOLD = '\033[1m'
    DIM = '\033[2m'
    UNDERLINE = '\033[4m'
    # 리셋
    RESET = '\033[0m'

    @classmethod
    def disable(cls):
        cls.RED = cls.GREEN = cls.YELLOW = cls.BLUE = ''
        cls.MAGENTA = cls.CYAN = cls.WHITE = ''
        cls.BOLD = cls.DIM = cls.UNDERLINE = cls.RESET = ''


# Windows 터미널 색상 지원 활성화
def init_colors():
    if sys.platform == 'win32':
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        except Exception:
            Colors.disable()


init_colors()


def log_info(msg):
    print(f"{Colors.CYAN}[*]{Colors.RESET} {msg}")


def log_success(msg):
    print(f"{Colors.GREEN}[+]{Colors.RESET} {msg}")


def log_error(msg):
    print(f"{Colors.RED}[ERROR]{Colors.RESET} {msg}")


def log_warning(msg):
    print(f"{Colors.YELLOW}[-]{Colors.RESET} {msg}")


def print_banner():
    C = Colors
    try:
        print(f"""
{C.CYAN}╔══════════════════════════════════════════════════════════╗
║{C.RESET}{C.BOLD}{C.GREEN}           NTFS Forensic Parser v{VERSION}                    {C.RESET}{C.CYAN}║
║{C.RESET}{C.YELLOW}     MFT / LogFile / UsnJrnl:$J Analysis Tool             {C.RESET}{C.CYAN}║
║                                                          ║
║{C.RESET}{C.WHITE}     Supports large files with streaming processing       {C.RESET}{C.CYAN}║
║{C.RESET}{C.WHITE}     Timezone: UTC+9 (KST)                                {C.RESET}{C.CYAN}║
║                                                          ║
║{C.RESET}{C.MAGENTA}     Author: {AUTHOR}                                     {C.RESET}{C.CYAN}║
╚══════════════════════════════════════════════════════════╝{C.RESET}
""")
    except UnicodeEncodeError:
        # Windows cp949 인코딩 대비 ASCII 버전
        print(f"""
{C.CYAN}+============================================================+
|{C.RESET}{C.BOLD}{C.GREEN}           NTFS Forensic Parser v{VERSION}                    {C.RESET}{C.CYAN}|
|{C.RESET}{C.YELLOW}     MFT / LogFile / UsnJrnl:$J Analysis Tool             {C.RESET}{C.CYAN}|
|                                                            |
|{C.RESET}{C.WHITE}     Supports large files with streaming processing       {C.RESET}{C.CYAN}|
|{C.RESET}{C.WHITE}     Timezone: UTC+9 (KST)                                {C.RESET}{C.CYAN}|
|                                                            |
|{C.RESET}{C.MAGENTA}     Author: {AUTHOR}                                     {C.RESET}{C.CYAN}|
+============================================================+{C.RESET}
""")


def parse_mft_command(args):
    from src.mft_parser import parse_mft_file, MFTParser

    input_path = args.input
    output_path = args.output
    output_format = args.format

    if not Path(input_path).exists():
        log_error(f"Input file not found: {input_path}")
        return 1

    log_info(f"Parsing MFT: {input_path}")
    log_info(f"Output: {output_path} ({output_format})")

    # 총 엔트리 수 계산
    parser = MFTParser(input_path)
    total = parser.get_total_entries()
    log_info(f"Total entries: {total:,}")

    start_time = datetime.now()

    try:
        parse_mft_file(
            input_path,
            output_path,
            include_deleted=not args.active_only,
            output_format=output_format,
            include_path=args.include_path
        )

        elapsed = (datetime.now() - start_time).total_seconds()
        log_success(f"Completed in {elapsed:.2f} seconds")
        log_success(f"Output saved to: {output_path}")
        return 0

    except Exception as e:
        log_error(f"Failed to parse MFT: {e}")
        return 1


def parse_usnjrnl_command(args):
    from src.usnjrnl_parser import parse_usnjrnl, parse_usnjrnl_streaming

    input_path = args.input
    output_path = args.output
    output_format = args.format
    mft_path = args.mft if hasattr(args, 'mft') else None

    if not Path(input_path).exists():
        log_error(f"Input file not found: {input_path}")
        return 1

    file_size = Path(input_path).stat().st_size
    log_info(f"Parsing UsnJrnl:$J: {input_path}")
    log_info(f"File size: {file_size / (1024*1024):.2f} MB")
    log_info(f"Output: {output_path} ({output_format})")

    if mft_path:
        log_info(f"Using MFT for path resolution: {mft_path}")

    start_time = datetime.now()

    try:
        if HAS_TQDM and file_size > 100 * 1024 * 1024:  # 100MB 이상
            pbar = tqdm(total=100, desc="Parsing", unit="%")
            last_progress = 0

            def progress_callback(progress, count):
                nonlocal last_progress
                current = int(progress * 100)
                if current > last_progress:
                    pbar.update(current - last_progress)
                    last_progress = current
                pbar.set_postfix(records=f"{count:,}")

            count = parse_usnjrnl_streaming(input_path, output_path,
                                            callback=progress_callback,
                                            output_format=output_format)
            pbar.close()
            log_success(f"Total records: {count:,}")
        else:
            parse_usnjrnl(
                input_path,
                output_path,
                mft_path=mft_path,
                output_format=output_format,
                include_path=bool(mft_path)
            )

        elapsed = (datetime.now() - start_time).total_seconds()
        log_success(f"Completed in {elapsed:.2f} seconds")
        log_success(f"Output saved to: {output_path}")
        return 0

    except Exception as e:
        log_error(f"Failed to parse UsnJrnl: {e}")
        import traceback
        traceback.print_exc()
        return 1


def parse_logfile_command(args):
    from src.logfile_parser import parse_logfile

    input_path = args.input
    output_path = args.output
    output_format = args.format

    if not Path(input_path).exists():
        log_error(f"Input file not found: {input_path}")
        return 1

    log_info(f"Parsing $LogFile: {input_path}")
    log_info(f"Output: {output_path} ({output_format})")

    start_time = datetime.now()

    try:
        parse_logfile(input_path, output_path, output_format=output_format)

        elapsed = (datetime.now() - start_time).total_seconds()
        log_success(f"Completed in {elapsed:.2f} seconds")
        log_success(f"Output saved to: {output_path}")
        return 0

    except Exception as e:
        log_error(f"Failed to parse LogFile: {e}")
        return 1


def analyze_command(args):
    from src.analyzer import UnifiedAnalyzer

    output_dir = args.output
    output_format = args.format

    log_info("Unified Analysis")
    log_info(f"Output directory: {output_dir}")

    mft_path = args.mft if hasattr(args, 'mft') and args.mft else None
    usnjrnl_path = args.usnjrnl if hasattr(args, 'usnjrnl') and args.usnjrnl else None
    logfile_path = args.logfile if hasattr(args, 'logfile') and args.logfile else None

    if not any([mft_path, usnjrnl_path, logfile_path]):
        log_error("At least one input file required (--mft, --usnjrnl, --logfile)")
        return 1

    if mft_path:
        log_info(f"MFT: {mft_path}")
    if usnjrnl_path:
        log_info(f"UsnJrnl: {usnjrnl_path}")
    if logfile_path:
        log_info(f"LogFile: {logfile_path}")

    start_time = datetime.now()

    try:
        analyzer = UnifiedAnalyzer(output_dir)
        result_path = analyzer.analyze_all(
            mft_path=mft_path,
            logfile_path=logfile_path,
            usnjrnl_path=usnjrnl_path,
            output_format=output_format
        )

        elapsed = (datetime.now() - start_time).total_seconds()
        log_success(f"Completed in {elapsed:.2f} seconds")
        log_success(f"Output saved to: {result_path}")
        return 0

    except Exception as e:
        log_error(f"Analysis failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


def extract_command(args):
    from src.image_handler import ImageHandler, find_ntfs_partitions, NTFSExtractor

    image_path = args.image
    output_dir = Path(args.output)
    verbose = args.verbose if hasattr(args, 'verbose') else False
    target_partition = args.partition if hasattr(args, 'partition') else None

    if not Path(image_path).exists():
        log_error(f"Image file not found: {image_path}")
        return 1

    output_dir.mkdir(parents=True, exist_ok=True)

    log_info(f"Opening image: {image_path}")

    # E01 파일 크기 표시
    file_size = Path(image_path).stat().st_size
    log_info(f"Image file size: {file_size / (1024*1024*1024):.2f} GB")

    try:
        with ImageHandler(image_path) as image:
            log_info(f"Media size (uncompressed): {image.size / (1024*1024*1024):.2f} GB")

            partitions = find_ntfs_partitions(image)
            log_info(f"Found {len(partitions)} NTFS partition(s)")

            # 특정 파티션만 처리할지 결정
            if target_partition is not None:
                if target_partition < 0 or target_partition >= len(partitions):
                    log_error(f"Invalid partition number: {target_partition} (valid: 0-{len(partitions)-1})")
                    return 1
                partitions_to_process = [(target_partition, partitions[target_partition])]
            else:
                partitions_to_process = list(enumerate(partitions))

            for i, partition in partitions_to_process:
                print()
                log_info(f"Processing partition {i + 1}")
                print(f"    Offset: {partition.offset}")
                print(f"    Cluster size: {partition.cluster_size}")
                print(f"    MFT offset: {partition.mft_offset}")

                extractor = NTFSExtractor(partition)

                # MFT 추출
                mft_path = output_dir / f"partition{i}_MFT"
                log_info("Extracting $MFT...")
                if extractor.extract_mft(str(mft_path)):
                    log_success(f"$MFT saved to: {mft_path}")
                else:
                    log_warning("Failed to extract $MFT")

                # LogFile 추출
                logfile_path = output_dir / f"partition{i}_LogFile"
                log_info("Extracting $LogFile...")
                if extractor.extract_logfile(str(logfile_path)):
                    log_success(f"$LogFile saved to: {logfile_path}")
                else:
                    log_warning("Failed to extract $LogFile")

                # UsnJrnl:$J 추출
                usnjrnl_path = output_dir / f"partition{i}_UsnJrnl_J"
                log_info("Extracting $UsnJrnl:$J...")
                if extractor.extract_usnjrnl(str(usnjrnl_path), verbose=verbose):
                    log_success(f"$UsnJrnl:$J saved to: {usnjrnl_path}")
                else:
                    log_warning("$UsnJrnl:$J not found (USN Journal may be disabled or deleted on this volume)")

        print()
        log_success("Extraction completed")
        return 0

    except ImportError as e:
        log_error(f"Missing dependency: {e}")
        log_info("For E01 support, install: pip install pyewf-python")
        return 1
    except Exception as e:
        log_error(f"Extraction failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


def extract_analyze_command(args):
    from src.image_handler import ImageHandler, find_ntfs_partitions, NTFSExtractor
    from src.mft_parser import parse_mft_file
    from src.usnjrnl_parser import parse_usnjrnl
    from src.logfile_parser import parse_logfile

    image_path = args.image
    output_dir = Path(args.output)
    verbose = args.verbose if hasattr(args, 'verbose') else False
    target_partition = args.partition if hasattr(args, 'partition') else None
    output_format = args.format if hasattr(args, 'format') else 'sqlite'
    skip_mft = args.skip_mft if hasattr(args, 'skip_mft') else False
    skip_usnjrnl = args.skip_usnjrnl if hasattr(args, 'skip_usnjrnl') else False
    skip_logfile = args.skip_logfile if hasattr(args, 'skip_logfile') else False

    if not Path(image_path).exists():
        log_error(f"Image file not found: {image_path}")
        return 1

    output_dir.mkdir(parents=True, exist_ok=True)
    temp_dir = output_dir / "temp_extracted"
    temp_dir.mkdir(parents=True, exist_ok=True)

    log_info(f"Opening image: {image_path}")
    log_info(f"Output directory: {output_dir}")
    log_info(f"Output format: {output_format}")

    file_size = Path(image_path).stat().st_size
    log_info(f"Image file size: {file_size / (1024*1024*1024):.2f} GB")

    start_time = datetime.now()

    try:
        with ImageHandler(image_path) as image:
            log_info(f"Media size (uncompressed): {image.size / (1024*1024*1024):.2f} GB")

            partitions = find_ntfs_partitions(image)
            log_info(f"Found {len(partitions)} NTFS partition(s)")

            if target_partition is not None:
                if target_partition < 0 or target_partition >= len(partitions):
                    log_error(f"Invalid partition number: {target_partition} (valid: 0-{len(partitions)-1})")
                    return 1
                partitions_to_process = [(target_partition, partitions[target_partition])]
            else:
                partitions_to_process = list(enumerate(partitions))

            for i, partition in partitions_to_process:
                print()
                log_info(f"{'='*50}")
                log_info(f"Processing partition {i}")
                log_info(f"{'='*50}")
                print(f"    Offset: {partition.offset}")
                print(f"    Cluster size: {partition.cluster_size}")

                extractor = NTFSExtractor(partition)

                # 파일 확장자 결정
                ext = '.db' if output_format == 'sqlite' else f'.{output_format}'

                # MFT 
                mft_temp_path = temp_dir / f"partition{i}_MFT"
                mft_output_path = output_dir / f"partition{i}_MFT{ext}"

                if not skip_mft:
                    print()
                    log_info("[1/3] MFT Extraction & Analysis")
                    log_info("Extracting $MFT...")
                    if extractor.extract_mft(str(mft_temp_path)):
                        log_success(f"$MFT extracted: {mft_temp_path}")
                        log_info(f"Analyzing MFT to {output_format}...")
                        try:
                            parse_mft_file(
                                str(mft_temp_path),
                                str(mft_output_path),
                                include_deleted=True,
                                output_format=output_format,
                                include_path=True
                            )
                            log_success(f"MFT analysis saved to: {mft_output_path}")
                        except Exception as e:
                            log_error(f"MFT analysis failed: {e}")
                    else:
                        log_warning("Failed to extract $MFT")
                        mft_temp_path = None

                # UsnJrnl 
                usnjrnl_temp_path = temp_dir / f"partition{i}_UsnJrnl_J"
                usnjrnl_output_path = output_dir / f"partition{i}_UsnJrnl{ext}"

                if not skip_usnjrnl:
                    print()
                    log_info("[2/3] UsnJrnl Extraction & Analysis")
                    log_info("Extracting $UsnJrnl:$J...")
                    if extractor.extract_usnjrnl(str(usnjrnl_temp_path), verbose=verbose):
                        log_success(f"$UsnJrnl:$J extracted: {usnjrnl_temp_path}")
                        usnjrnl_size = usnjrnl_temp_path.stat().st_size
                        log_info(f"UsnJrnl size: {usnjrnl_size / (1024*1024):.2f} MB")
                        log_info(f"Analyzing UsnJrnl to {output_format}...")
                        try:
                            # MFT 경로 연동 (추출된 경우)
                            mft_for_path = str(mft_temp_path) if (not skip_mft and mft_temp_path and mft_temp_path.exists()) else None
                            parse_usnjrnl(
                                str(usnjrnl_temp_path),
                                str(usnjrnl_output_path),
                                mft_path=mft_for_path,
                                output_format=output_format,
                                include_path=bool(mft_for_path)
                            )
                            log_success(f"UsnJrnl analysis saved to: {usnjrnl_output_path}")
                        except Exception as e:
                            log_error(f"UsnJrnl analysis failed: {e}")
                    else:
                        log_warning("$UsnJrnl:$J not found (USN Journal may be disabled)")

                # LogFile 
                logfile_temp_path = temp_dir / f"partition{i}_LogFile"
                logfile_output_path = output_dir / f"partition{i}_LogFile{ext}"

                if not skip_logfile:
                    print()
                    log_info("[3/3] LogFile Extraction & Analysis")
                    log_info("Extracting $LogFile...")
                    if extractor.extract_logfile(str(logfile_temp_path)):
                        log_success(f"$LogFile extracted: {logfile_temp_path}")
                        log_info(f"Analyzing LogFile to {output_format}...")
                        try:
                            # LogFile은 sqlite 미지원시 csv로 fallback
                            logfile_format = output_format if output_format != 'sqlite' else 'csv'
                            if output_format == 'sqlite':
                                logfile_output_path = output_dir / f"partition{i}_LogFile.csv"
                                log_warning("LogFile sqlite not supported, using CSV")
                            parse_logfile(str(logfile_temp_path), str(logfile_output_path), output_format=logfile_format)
                            log_success(f"LogFile analysis saved to: {logfile_output_path}")
                        except Exception as e:
                            log_error(f"LogFile analysis failed: {e}")
                    else:
                        log_warning("Failed to extract $LogFile")

        # 임시 파일 정리 옵션
        if not args.keep_temp:
            print()
            log_info("Cleaning up temporary files...")
            import shutil
            try:
                shutil.rmtree(temp_dir)
                log_success("Temporary files removed")
            except Exception as e:
                log_warning(f"Failed to remove temp files: {e}")

        elapsed = (datetime.now() - start_time).total_seconds()
        print()
        log_info(f"{'='*50}")
        log_success(f"All-in-one extraction and analysis completed!")
        log_success(f"Total time: {elapsed:.2f} seconds")
        log_success(f"Output directory: {output_dir}")
        log_info(f"{'='*50}")
        return 0

    except ImportError as e:
        log_error(f"Missing dependency: {e}")
        log_info("For E01 support, install: pip install pyewf-python")
        return 1
    except Exception as e:
        log_error(f"Extract-analyze failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


def main():
    print_banner()

    C = Colors
    usage_examples = f"""
{C.BOLD}{C.YELLOW}Usage:{C.RESET}
  python ntfs_parser.py <command> [options]

{C.BOLD}{C.YELLOW}Commands:{C.RESET}
  {C.GREEN}extract-analyze{C.RESET}  이미지에서 추출 + 분석
  {C.GREEN}extract{C.RESET}          이미지에서 아티팩트 추출
  {C.GREEN}parse-mft{C.RESET}        $MFT 파일 분석
  {C.GREEN}parse-usnjrnl{C.RESET}    $UsnJrnl:$J 파일 분석
  {C.GREEN}parse-logfile{C.RESET}    $LogFile 분석
  {C.GREEN}analyze{C.RESET}          추출된 아티팩트 통합 분석

{C.BOLD}{C.YELLOW}Examples:{C.RESET}
  python ntfs_parser.py extract-analyze --image <image_file> -o <output_dir> [-p <partition>] [-f <format>]
  python ntfs_parser.py extract --image <image_file> -o <output_dir>
  python ntfs_parser.py parse-mft -i <mft_file> -o <output> [-f <format>]
  python ntfs_parser.py analyze --mft <mft_file> --usnjrnl <usnjrnl_file> --logfile <logfile> -o <output_dir>

{C.BOLD}{C.YELLOW}Common Options:{C.RESET}
  {C.CYAN}-i, --input{C.RESET}       입력 파일 경로 (아티팩트 파일)
  {C.CYAN}-o, --output{C.RESET}      출력 파일/디렉토리 경로
  {C.CYAN}-f, --format{C.RESET}      출력 형식: csv, json, sqlite (기본: csv, extract-analyze는 sqlite)
  {C.CYAN}-p, --partition{C.RESET}   특정 파티션만 처리 (0부터 시작)
  {C.CYAN}--image{C.RESET}           디스크 이미지 파일 경로 (E01, RAW)
  {C.CYAN}--mft{C.RESET}             $MFT 파일 경로 (경로 복원용)
  {C.CYAN}--active-only{C.RESET}     활성 엔트리만 출력 (parse-mft)
  {C.CYAN}--keep-temp{C.RESET}       임시 추출 파일 유지 (extract-analyze)
  {C.CYAN}--skip-mft{C.RESET}        MFT 추출/분석 스킵
  {C.CYAN}--skip-usnjrnl{C.RESET}    UsnJrnl 추출/분석 스킵
  {C.CYAN}--skip-logfile{C.RESET}    LogFile 추출/분석 스킵
  {C.CYAN}-v, --verbose{C.RESET}     상세 디버그 출력
"""

    parser = argparse.ArgumentParser(
        description="NTFS Forensic Parser - Analyze MFT, LogFile, UsnJrnl",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=usage_examples
    )

    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # parse-mft 명령
    mft_parser = subparsers.add_parser('parse-mft', help='Parse $MFT file')
    mft_parser.add_argument('-i', '--input', required=True, help='Path to $MFT file')
    mft_parser.add_argument('-o', '--output', required=True, help='Output file path')
    mft_parser.add_argument('-f', '--format', choices=['csv', 'json', 'sqlite'], default='csv',
                            help='Output format (default: csv)')
    mft_parser.add_argument('--active-only', action='store_true',
                            help='Only include active (in-use) entries')
    mft_parser.add_argument('--include-path', action='store_true', default=True,
                            help='Include full path (may increase processing time)')

    # parse-usnjrnl 명령
    usn_parser = subparsers.add_parser('parse-usnjrnl', help='Parse $UsnJrnl:$J file')
    usn_parser.add_argument('-i', '--input', required=True, help='Path to $J file')
    usn_parser.add_argument('-o', '--output', required=True, help='Output file path')
    usn_parser.add_argument('-f', '--format', choices=['csv', 'json', 'sqlite'], default='csv',
                            help='Output format (default: csv)')
    usn_parser.add_argument('--mft', help='Path to $MFT for path resolution')

    # parse-logfile 명령
    log_parser = subparsers.add_parser('parse-logfile', help='Parse $LogFile')
    log_parser.add_argument('-i', '--input', required=True, help='Path to $LogFile')
    log_parser.add_argument('-o', '--output', required=True, help='Output file path')
    log_parser.add_argument('-f', '--format', choices=['csv', 'json'], default='csv',
                            help='Output format (default: csv)')

    # analyze 명령
    analyze_parser = subparsers.add_parser('analyze', help='Unified analysis of all artifacts')
    analyze_parser.add_argument('--mft', help='Path to $MFT file')
    analyze_parser.add_argument('--usnjrnl', help='Path to $J file')
    analyze_parser.add_argument('--logfile', help='Path to $LogFile')
    analyze_parser.add_argument('-o', '--output', required=True, help='Output directory')
    analyze_parser.add_argument('-f', '--format', choices=['csv', 'json', 'sqlite'],
                                default='csv', help='Output format (default: csv)')

    # extract 명령
    extract_parser = subparsers.add_parser('extract', help='Extract artifacts from disk image')
    extract_parser.add_argument('--image', required=True, help='Path to disk image (E01, RAW)')
    extract_parser.add_argument('-o', '--output', required=True, help='Output directory')
    extract_parser.add_argument('-p', '--partition', type=int, help='Extract only specific partition (0-based index)')
    extract_parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose debug output')

    # extract-analyze 명령 (올인원)
    ea_parser = subparsers.add_parser('extract-analyze', help='Extract and analyze to DB in one step')
    ea_parser.add_argument('--image', required=True, help='Path to disk image (E01, RAW)')
    ea_parser.add_argument('-o', '--output', required=True, help='Output directory')
    ea_parser.add_argument('-p', '--partition', type=int, help='Process only specific partition (0-based index)')
    ea_parser.add_argument('-f', '--format', choices=['csv', 'json', 'sqlite'], default='sqlite',
                           help='Output format (default: sqlite)')
    ea_parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose debug output')
    ea_parser.add_argument('--keep-temp', action='store_true', help='Keep temporary extracted files')
    ea_parser.add_argument('--skip-mft', action='store_true', help='Skip MFT extraction/analysis')
    ea_parser.add_argument('--skip-usnjrnl', action='store_true', help='Skip UsnJrnl extraction/analysis')
    ea_parser.add_argument('--skip-logfile', action='store_true', help='Skip LogFile extraction/analysis')

    args = parser.parse_args()

    if args.command == 'parse-mft':
        return parse_mft_command(args)
    elif args.command == 'parse-usnjrnl':
        return parse_usnjrnl_command(args)
    elif args.command == 'parse-logfile':
        return parse_logfile_command(args)
    elif args.command == 'analyze':
        return analyze_command(args)
    elif args.command == 'extract':
        return extract_command(args)
    elif args.command == 'extract-analyze':
        return extract_analyze_command(args)
    else:
        parser.print_help()
        return 0


if __name__ == '__main__':
    sys.exit(main())
