; ===========================================================================
; L1 解密 stub v2 —— ASLR-preserving (x64, MASM/ml64)
;
; 与 stub.asm 的区别: 不再依赖 strip-relocs/固定 ImageBase。运行时从 PEB 读
; 真实加载基址 (ASLR 每次不同), 再用 baked 的 RVA 算出 .text VA 与 OEP VA。
; 前提(已测量): x64 exe 的 .text 段内无 base relocation, 故只加密 .text 不会
; 被 loader 的 reloc 修正破坏 → 可保留 relocs, 主模块 ASLR 存活。
;
; r15 全程保存真实基址 (解密循环不碰 r15)。
;
; 占位常量 (加壳器按唯一字节模式 patch):
;   P_TEXTRVA = 1111111111111111h  .text 段 RVA
;   P_LEN     = 2222222222222222h  解密字节数
;   P_SEED    = 33333333h          LCG 初始 state
;   P_OEPRVA  = 4444444444444444h  原始入口点 RVA
; ===========================================================================

_TEXT SEGMENT
PUBLIC stub_start

stub_start PROC
    mov     rax, gs:[60h]              ; rax = PEB
    mov     r15, [rax + 10h]           ; r15 = PEB.ImageBaseAddress (真实基址)

    mov     rsi, r15
    mov     rax, 1111111111111111h     ; P_TEXTRVA
    add     rsi, rax                   ; rsi = .text VA
    mov     rcx, 2222222222222222h     ; P_LEN
    mov     edx, 33333333h             ; P_SEED

decrypt_loop:
    imul    edx, edx, 000343FDh
    add     edx, 00269EC3h
    mov     eax, edx
    shr     eax, 16
    xor     byte ptr [rsi], al
    inc     rsi
    dec     rcx
    jnz     decrypt_loop

    mov     rax, 4444444444444444h     ; P_OEPRVA
    add     rax, r15                   ; rax = 原始 OEP VA
    jmp     rax
stub_start ENDP

_TEXT ENDS
END
