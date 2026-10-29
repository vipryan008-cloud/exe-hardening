"""从 ml64 生成的 COFF .obj 里抽出指定段(默认 _TEXT/.text)的原始机器码字节。

COFF 头很简单, 不引第三方: 解析 section table, 找到名字匹配的段,
返回其 [PointerToRawData, +SizeOfRawData) 原始字节 = 我们要的 shellcode。
"""
import struct
import sys


def extract_section(obj_path: str, want_prefixes=(b".text", b"_TEXT")) -> bytes:
    data = open(obj_path, "rb").read()
    # COFF header: Machine(2) NumSec(2) TimeDate(4) PtrSymTab(4) NumSym(4) OptHdrSz(2) Char(2) = 20 bytes
    num_sections = struct.unpack_from("<H", data, 2)[0]
    opt_hdr_sz = struct.unpack_from("<H", data, 16)[0]
    sec_tab = 20 + opt_hdr_sz
    for i in range(num_sections):
        off = sec_tab + i * 40
        name = data[off:off + 8].rstrip(b"\x00")
        size_raw = struct.unpack_from("<I", data, off + 16)[0]
        ptr_raw = struct.unpack_from("<I", data, off + 20)[0]
        if any(name.startswith(p) for p in want_prefixes):
            return data[ptr_raw:ptr_raw + size_raw]
    raise SystemExit(f"section {want_prefixes} not found in {obj_path}; have "
                     f"{[data[sec_tab+i*40:sec_tab+i*40+8].rstrip(chr(0).encode()) for i in range(num_sections)]}")


if __name__ == "__main__":
    b = extract_section(sys.argv[1])
    sys.stdout.buffer.write(b)
