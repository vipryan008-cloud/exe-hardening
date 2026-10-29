; ===========================================================================
; L1 整体壳 — 解密 stub (x64, MASM/ml64)
;
; 运行时职责: 把加壳时被加密的 .text 段就地解回明文, 然后跳到原始 OEP。
; 前提(加壳器保证): relocs 已 strip + 固定 ImageBase, 所以下面 4 个 VA/常量
; 可以在加壳时按 "ImageBase + RVA" 直接算好, 以立即数形式补丁进本 stub。
;
; 加密算法: MSVC rand() 同款 LCG 生成密钥流 (state = state*343FDh + 269EC3h,
; 取 bit16..23 作密钥字节)。加壳器 Python 侧必须逐字节镜像同一算法。
;
; 4 个占位常量 (加壳器按唯一字节模式搜索并 patch):
;   P_TEXTVA = 1111111111111111h  原 .text 段在内存中的绝对 VA
;   P_LEN    = 2222222222222222h  要解密的字节数 = min(VirtualSize, RawSize)
;   P_SEED   = 33333333h          LCG 初始 state (32bit)
;   P_OEPVA  = 4444444444444444h  原始入口点绝对 VA
; ===========================================================================

_TEXT SEGMENT
PUBLIC stub_start

stub_start PROC
    mov     rsi, 1111111111111111h      ; rsi = P_TEXTVA  (48 BE + imm64)
    mov     rcx, 2222222222222222h      ; rcx = P_LEN     (48 B9 + imm64)
    mov     edx, 33333333h              ; edx = P_SEED    (BA + imm32)

decrypt_loop:
    imul    edx, edx, 000343FDh         ; LCG: state = state*343FD
    add     edx, 00269EC3h              ;            + 269EC3
    mov     eax, edx
    shr     eax, 16                     ; 密钥字节 = (state >> 16) & 0xFF
    xor     byte ptr [rsi], al
    inc     rsi
    dec     rcx
    jnz     decrypt_loop

    mov     rax, 4444444444444444h      ; rax = P_OEPVA   (48 B8 + imm64)
    jmp     rax                         ; 跳原始入口, 交还给原程序 CRT
stub_start ENDP

_TEXT ENDS
END
