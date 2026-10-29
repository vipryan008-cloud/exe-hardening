"""编译 f.c → 反汇编 f() → 翻译成 VM 字节码 → 写 f_bc.h。"""
import struct
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import x86_to_vm


def coff_text(obj):
    d = open(obj, "rb").read()
    nsec = struct.unpack_from("<H", d, 2)[0]
    optsz = struct.unpack_from("<H", d, 16)[0]
    st = 20 + optsz
    for i in range(nsec):
        o = st + i * 40
        if d[o:o + 8].rstrip(b"\x00").startswith(b".text"):
            sr = struct.unpack_from("<I", d, o + 16)[0]
            pr = struct.unpack_from("<I", d, o + 20)[0]
            return d[pr:pr + sr]
    raise SystemExit("no .text")


def main(obj, name="f_bc"):
    code = coff_text(obj)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    print("f() x86 (至 int3 填充止):")
    for ins in md.disasm(code, 0):
        if ins.mnemonic == "int3":
            break
        print(f"  0x{ins.address:04x}: {ins.mnemonic:8} {ins.op_str}")
    bc = x86_to_vm.translate(code)     # translate 自行在 int3 处停, 处理分支/多 ret
    print(f"VM 字节码 ({len(bc)} bytes): {bc.hex()}")
    open(f"{name}.h", "w").write(x86_to_vm.to_c_array(bc, name))
    print(f"wrote {name}.h")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "f.obj",
         sys.argv[2] if len(sys.argv) > 2 else "f_bc")
