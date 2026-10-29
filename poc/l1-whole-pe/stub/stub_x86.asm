; ===========================================================================
; L1 整体壳 — 解密 stub (x86 / 32位, MASM/ml)
;
; x64 版 stub.asm 的 32 位移植。职责相同: 就地解密被加壳时加密的 .text 段,
; 然后跳原始 OEP。strip-relocs + 固定 ImageBase 模式 → 4 个常量按绝对 VA baked。
; x86 差异: 寄存器 e** (32位), VA/长度/OEP 是 32 位立即数(4字节占位, 非8字节)。
;
; 加密算法与 x64/Python 侧一致: MSVC rand LCG (state=state*343FDh+269EC3h, bit16..23)。
;
; 占位常量 (加壳器按唯一 4 字节模式搜索并 patch):
;   P_TEXTVA = 11111111h  原 .text 段绝对 VA (ImageBase+RVA)
;   P_LEN    = 22222222h  解密字节数
;   P_SEED   = 33333333h  LCG 初始 state
;   P_OEPVA  = 44444444h  原始入口点绝对 VA
; ===========================================================================
.386
.model flat, C

_TEXT SEGMENT USE32
PUBLIC stub_start

stub_start PROC
    mov     esi, 11111111h              ; esi = P_TEXTVA  (BE + imm32)
    mov     ecx, 22222222h              ; ecx = P_LEN     (B9 + imm32)
    mov     edx, 33333333h              ; edx = P_SEED    (BA + imm32)

decrypt_loop:
    imul    edx, edx, 000343FDh         ; state = state*343FD
    add     edx, 00269EC3h              ;       + 269EC3
    mov     eax, edx
    shr     eax, 16                     ; key = (state>>16) & 0xFF
    xor     byte ptr [esi], al
    inc     esi
    dec     ecx
    jnz     decrypt_loop

    mov     eax, 44444444h              ; eax = P_OEPVA   (B8 + imm32)
    jmp     eax                         ; 跳原始入口
stub_start ENDP

_TEXT ENDS
END
