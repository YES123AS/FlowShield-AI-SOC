import os
import time
from pathlib import Path

from werkzeug.utils import secure_filename


ALLOWED_PCAP_EXTENSIONS = {"pcap", "pcapng"}
PCAP_MAGIC_NUMBERS = {
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\xc3\xd4",
    b"\x4d\x3c\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
    b"\x0a\x0d\x0d\x0a"
}


def allowed_pcap_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_PCAP_EXTENSIONS


def has_valid_pcap_magic(file_storage):
    pos = file_storage.stream.tell()
    header = file_storage.stream.read(4)
    file_storage.stream.seek(pos)
    return header in PCAP_MAGIC_NUMBERS


def build_safe_upload_path(upload_dir, original_filename):
    safe_name = secure_filename(original_filename)
    if not safe_name:
        raise ValueError("文件名不合法")

    stem = Path(safe_name).stem
    suffix = Path(safe_name).suffix.lower()
    filename = f"{stem}_{int(time.time())}{suffix}"
    upload_root = Path(upload_dir).resolve()
    upload_root.mkdir(parents=True, exist_ok=True)
    path = (upload_root / filename).resolve()

    if upload_root not in path.parents and path != upload_root:
        raise ValueError("上传路径不合法")

    return str(path), filename


def validate_pcap_upload(file_storage):
    if not file_storage or not file_storage.filename:
        return False, "没有选择文件"
    if not allowed_pcap_file(file_storage.filename):
        return False, "仅支持 .pcap 或 .pcapng 文件"
    if not has_valid_pcap_magic(file_storage):
        return False, "文件头校验失败，请上传真实的 PCAP/PCAPNG 文件"
    return True, ""
