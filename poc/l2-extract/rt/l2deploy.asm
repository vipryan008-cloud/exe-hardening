; ===========================================================================
; L2 单文件部署 blob (x64, MASM) —— 自包含 PIC, 供 packer 嵌入 .l2rt 段。
; 布局(全在一个 _TEXT 段, 内部引用全 RIP-relative → 位置无关):
;   [l2_entry][l2_install][l2_handler][get_kernel32_base][get_proc][数据/字符串][g_tbl:]
; packer 把本 blob 放进新段(标记 RWX), 段起点=l2_entry=新入口; 在 g_tbl 处追加
; 侧表[count][entries][stash]; 并 patch l2_entry 里的 P_OEPRVA 占位。
; 运行: l2_entry 取 PEB 基址 → l2_install(表,基址) 自解析+装VEH → jmp 原OEP。
; 之后被抽函数(int3)首次执行 → VEH 从表解密回填。
; ===========================================================================

STASH_XOR   equ 0A7h
EXC_BP      equ 80000003h
CONT_EXEC   equ 0FFFFFFFFh
CONT_SEARCH equ 0
CTX_RIP     equ 0F8h
PAGE_RWX    equ 40h

_TEXT SEGMENT

; ---------------------------------------------------------------------------
; 新入口: 取真实基址 → 调 l2_install(g_tbl, base) → jmp 原OEP(base+P_OEPRVA)
; ---------------------------------------------------------------------------
PUBLIC l2_entry
l2_entry PROC
    mov     rax, gs:[60h]
    mov     r15, [rax+10h]             ; r15 = image base

    ; --- 可选反调试 (P_ANTIDBG != 0 时启用) —— 纯 PEB 读, 无 API, 无误报 ---
    mov     r14d, 55555555h            ; P_ANTIDBG (packer patch; 0=关)
    test    r14d, r14d
    jz      no_antidbg
    movzx   ecx, byte ptr [rax+2]      ; PEB.BeingDebugged
    mov     edx, [rax+0BCh]            ; PEB.NtGlobalFlag
    and     edx, 70h                   ; heap 调试标志
    or      ecx, edx
    jz      no_antidbg                 ; 干净 → 继续
    ; 命中调试器 → ExitProcess(42) 处置
    call    get_kernel32_base
    mov     rcx, rax
    lea     rdx, s_exit
    call    get_proc                   ; rax = ExitProcess
    mov     rcx, 42
    sub     rsp, 28h
    call    rax                        ; 不返回
no_antidbg:

    ; --- 可选 L1 整体解密 (P_LEN==0 则跳过, 用于纯 L2 模式) ---
    mov     rcx, 2222222222222222h     ; P_LEN (packer patch; 0=不解密)
    test    rcx, rcx
    jz      no_decrypt
    mov     rsi, r15
    mov     rax, 1111111111111111h     ; P_TEXTRVA
    add     rsi, rax                   ; .text VA
    mov     edx, 33333333h             ; P_SEED
l1_dec:
    imul    edx, edx, 000343FDh
    add     edx, 00269EC3h
    mov     eax, edx
    shr     eax, 16
    xor     byte ptr [rsi], al
    inc     rsi
    dec     rcx
    jnz     l1_dec
no_decrypt:

    lea     rcx, g_tbl                 ; 侧表 VA (RIP-relative, blob 末尾)
    mov     rdx, r15                   ; base
    sub     rsp, 28h
    call    l2_install
    add     rsp, 28h
    mov     rax, 4444444444444444h     ; P_OEPRVA (packer patch)
    add     rax, r15
    jmp     rax
l2_entry ENDP

; ---------------------------------------------------------------------------
l2_install PROC                        ; rcx=table, rdx=base
    push    rbx
    push    rsi
    push    rdi
    sub     rsp, 20h

    lea     rbx, g_table
    mov     [rbx], rcx
    lea     rsi, g_base
    mov     [rsi], rdx

    call    get_kernel32_base
    mov     rbx, rax                   ; base

    mov     rcx, rbx
    lea     rdx, s_gpa
    call    get_proc
    mov     rdi, rax                   ; GetProcAddress

    mov     rcx, rbx
    lea     rdx, s_vp
    call    rdi
    lea     rcx, p_VP
    mov     [rcx], rax

    mov     rcx, rbx
    lea     rdx, s_flush
    call    rdi
    lea     rcx, p_Flush
    mov     [rcx], rax

    ; TLS API (call-gate per-thread 影子栈用)
    mov     rcx, rbx
    lea     rdx, s_tlsg
    call    rdi
    lea     rcx, p_TlsGet
    mov     [rcx], rax
    mov     rcx, rbx
    lea     rdx, s_tlss
    call    rdi
    lea     rcx, p_TlsSet
    mov     [rcx], rax
    mov     rcx, rbx
    lea     rdx, s_valloc
    call    rdi
    lea     rcx, p_VAlloc
    mov     [rcx], rax
    mov     rcx, rbx
    lea     rdx, s_tlsa
    call    rdi
    call    rax                        ; TlsAlloc() -> eax = idx
    lea     rcx, g_tlsidx
    mov     [rcx], eax

    mov     rcx, rbx
    lea     rdx, s_av
    call    rdi
    mov     rcx, 1
    lea     rdx, l2_handler
    call    rax

    add     rsp, 20h
    pop     rdi
    pop     rsi
    pop     rbx
    ret
l2_install ENDP

; ---------------------------------------------------------------------------
l2_handler PROC                        ; rcx = PEXCEPTION_POINTERS
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 30h

    mov     r12, rcx
    mov     rax, [r12]                 ; ExceptionRecord
    mov     ecx, [rax]
    cmp     ecx, EXC_BP
    jne     h_pass
    mov     r13, [rax+10h]             ; 故障地址

    lea     rbx, g_table
    mov     rbx, [rbx]
    test    rbx, rbx
    jz      h_pass
    lea     rax, g_base
    mov     r14, [rax]
    mov     r15, [rbx]                 ; count
    lea     rsi, [rbx+8]               ; entry[0]
    xor     rdi, rdi
h_loop:
    cmp     rdi, r15
    jae     h_pass
    mov     rax, [rsi]
    add     rax, r14                   ; entry_va
    mov     rcx, [rsi+8]              ; len
    cmp     r13, rax
    jb      h_nextentry
    lea     rdx, [rax+rcx]
    cmp     r13, rdx
    jae     h_nextentry
    ; 命中
    mov     rbx, rax                   ; entry_va
    mov     r15, rcx                   ; len
    mov     r14, [rsi+10h]            ; stash_off
    lea     rax, g_table
    mov     rax, [rax]
    add     r14, rax                   ; stash_ptr

    mov     rcx, rbx
    mov     rdx, r15
    mov     r8d, PAGE_RWX
    lea     r9, [rsp+20h]
    lea     rax, p_VP
    call    qword ptr [rax]

    xor     rcx, rcx
h_dec:
    cmp     rcx, r15
    jae     h_decdone
    movzx   eax, byte ptr [r14+rcx]
    xor     al, STASH_XOR
    mov     byte ptr [rbx+rcx], al
    inc     rcx
    jmp     h_dec
h_decdone:
    mov     rcx, rbx
    mov     rdx, r15
    mov     r8d, dword ptr [rsp+20h]
    lea     r9, [rsp+20h]
    lea     rax, p_VP
    call    qword ptr [rax]

    mov     rcx, -1
    mov     rdx, rbx
    mov     r8, r15
    lea     rax, p_Flush
    call    qword ptr [rax]

    ; --- 可选 call-gate: 把返回地址改成 restub_tramp, 压 per-thread 影子栈 (rbx=entry_va, r15=len) ---
    mov     eax, 66666666h            ; P_CALLGATE (packer patch; 0=关)
    test    eax, eax
    jz      no_hook
    mov     rax, [r12+8]              ; ContextRecord
    mov     rcx, [rax+98h]            ; CONTEXT.Rsp (函数入口处 [Rsp]=返回地址)
    mov     rdx, [rcx]                ; realret
    mov     [rsp+20h], rcx            ; 存 rsp_ptr (handler 帧 0x20..0x30 空闲)
    mov     [rsp+28h], rdx            ; 存 realret
    call    get_shadow                ; rax = 本线程影子栈 (保留 rbx/r15/r12)
    mov     rcx, [rax]                ; sp
    mov     r8, rcx
    imul    r8, r8, 24
    lea     r9, [rax+8]
    add     r9, r8                    ; &frame
    mov     [r9], rbx                 ; entry_va
    mov     [r9+8], r15               ; len
    mov     r10, [rsp+28h]            ; realret
    mov     [r9+16], r10
    inc     rcx
    mov     [rax], rcx                ; sp++
    mov     rcx, [rsp+20h]            ; rsp_ptr
    lea     rax, restub_tramp
    mov     [rcx], rax                ; [Rsp] = 蹦床
no_hook:
    mov     rax, [r12+8]               ; ContextRecord
    mov     [rax+CTX_RIP], rbx
    mov     eax, CONT_EXEC
    jmp     h_done
h_nextentry:
    add     rsi, 24
    inc     rdi
    jmp     h_loop
h_pass:
    mov     eax, CONT_SEARCH
h_done:
    add     rsp, 30h
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
l2_handler ENDP

; ---------------------------------------------------------------------------
; 用完即擦返回蹦床: 被保护函数 ret 落此 → 弹影子栈 + 把该函数重抽 int3 → jmp 真返回地址。
; 保留整型返回值 rax/rdx (浮点/结构体返回未处理, 见 docs 边界)。
; ---------------------------------------------------------------------------
restub_tramp PROC
    push    rax                        ; 保存整型返回值
    push    rdx
    push    rbp                        ; rbp 非易失, realret 代码需要
    mov     rbp, rsp                   ; 锚点(可能未对齐)
    and     rsp, -16                   ; 强制 16 对齐 (被保护函数可能在 rsp%16==8 处被调, 如 __chkstk 在序言中途)
    sub     rsp, 60h                   ; shadow@0..0x20, 局部@0x20..0x40, xmm@0x40/0x50
    movdqu  [rsp+40h], xmm0            ; 保存浮点/向量返回值
    movdqu  [rsp+50h], xmm1
    ; 弹 per-thread 影子栈: sp--, 取 frame
    call    get_shadow                  ; rax = 本线程影子栈
    mov     rcx, [rax]                  ; sp
    dec     rcx
    mov     [rax], rcx                  ; sp--
    lea     rdx, [rax+8]                ; frames
    imul    rcx, rcx, 24
    add     rdx, rcx                    ; &frame
    mov     r8, [rdx]                   ; entry_va
    mov     r9, [rdx+8]                 ; len
    mov     r10, [rdx+16]               ; realret
    mov     [rsp+28h], r8
    mov     [rsp+30h], r9
    mov     [rsp+38h], r10
    ; VirtualProtect(entry_va, len, RWX, &old@rsp+20)
    mov     rcx, r8
    mov     rdx, r9
    mov     r8d, PAGE_RWX
    lea     r9, [rsp+20h]
    lea     rax, p_VP
    call    qword ptr [rax]
    ; 填 int3
    mov     rcx, [rsp+28h]
    mov     rdx, [rsp+30h]
rt_fill:
    test    rdx, rdx
    jz      rt_filld
    mov     byte ptr [rcx], 0CCh
    inc     rcx
    dec     rdx
    jmp     rt_fill
rt_filld:
    ; 还原保护
    mov     rcx, [rsp+28h]
    mov     rdx, [rsp+30h]
    mov     r8d, dword ptr [rsp+20h]
    lea     r9, [rsp+20h]
    lea     rax, p_VP
    call    qword ptr [rax]
    ; FlushInstructionCache(-1, entry_va, len)
    mov     rcx, -1
    mov     rdx, [rsp+28h]
    mov     r8, [rsp+30h]
    lea     rax, p_Flush
    call    qword ptr [rax]
    mov     r11, [rsp+38h]             ; realret
    movdqu  xmm0, [rsp+40h]            ; 恢复浮点/向量返回值
    movdqu  xmm1, [rsp+50h]
    mov     rsp, rbp                   ; 恢复到对齐前
    pop     rbp
    pop     rdx
    pop     rax                         ; 恢复整型返回值
    jmp     r11
restub_tramp ENDP

; ---------------------------------------------------------------------------
; get_shadow: 返回本线程影子栈 {sp:q; frames[128]*24}, 首次用时 VirtualAlloc + TlsSetValue。
; 结果 rax = 结构指针。(TLS 使 call-gate 多线程安全)
; ---------------------------------------------------------------------------
get_shadow PROC
    sub     rsp, 28h
    lea     rax, g_tlsidx
    mov     ecx, [rax]
    lea     rax, p_TlsGet
    call    qword ptr [rax]            ; TlsGetValue(idx)
    test    rax, rax
    jnz     gs_have
    xor     rcx, rcx                   ; VirtualAlloc(NULL, 4096, COMMIT|RESERVE, RW)
    mov     edx, 4096
    mov     r8d, 3000h
    mov     r9d, 4
    lea     rax, p_VAlloc
    call    qword ptr [rax]            ; rax = 新块 (零初始化 → sp=0)
    mov     r10, rax
    lea     rax, g_tlsidx
    mov     ecx, [rax]
    mov     rdx, r10
    lea     rax, p_TlsSet
    call    qword ptr [rax]            ; TlsSetValue(idx, 块)
    mov     rax, r10
gs_have:
    add     rsp, 28h
    ret
get_shadow ENDP

; ---------------------------------------------------------------------------
get_kernel32_base PROC
    mov     rax, gs:[60h]
    mov     rax, [rax+18h]
    lea     rdx, [rax+10h]
    mov     rcx, [rdx]
gk_walk:
    cmp     rcx, rdx
    je      gk_none
    movzx   r8, word ptr [rcx+58h]
    mov     r9, [rcx+60h]
    xor     eax, eax
    xor     r10, r10
gk_hash:
    cmp     r10, r8
    jae     gk_test
    movzx   r11d, byte ptr [r9+r10]
    cmp     r11b, 61h
    jb      gk_noup
    cmp     r11b, 7Ah
    ja      gk_noup
    sub     r11b, 20h
gk_noup:
    ror     eax, 13
    add     eax, r11d
    inc     r10
    jmp     gk_hash
gk_test:
    cmp     eax, 6A4ABC5Bh
    jne     gk_next
    mov     rax, [rcx+30h]
    ret
gk_next:
    mov     rcx, [rcx]
    jmp     gk_walk
gk_none:
    xor     eax, eax
    ret
get_kernel32_base ENDP

; ---------------------------------------------------------------------------
get_proc PROC                          ; rcx=base rdx=name -> rax
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    mov     rbx, rcx
    mov     rsi, rdx
    mov     eax, [rbx+3Ch]
    lea     r12, [rbx+rax]
    mov     eax, [r12+88h]
    test    eax, eax
    jz      gp_fail
    lea     r13, [rbx+rax]
    mov     r14d, [r13+18h]
    mov     r8d, [r13+20h]
    lea     r8, [rbx+r8]
    xor     r9, r9
gp_loop:
    cmp     r9, r14
    jae     gp_fail
    mov     eax, [r8+r9*4]
    lea     rdi, [rbx+rax]
    mov     r10, rdi
    mov     r11, rsi
gp_cmp:
    mov     al, [r10]
    cmp     al, [r11]
    jne     gp_nextname
    test    al, al
    je      gp_found
    inc     r10
    inc     r11
    jmp     gp_cmp
gp_nextname:
    inc     r9
    jmp     gp_loop
gp_found:
    mov     eax, [r13+24h]
    lea     rax, [rbx+rax]
    movzx   eax, word ptr [rax+r9*2]
    mov     ecx, [r13+1Ch]
    lea     rcx, [rbx+rcx]
    mov     eax, [rcx+rax*4]
    lea     rax, [rbx+rax]
    jmp     gp_done
gp_fail:
    xor     rax, rax
gp_done:
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
get_proc ENDP

; ---- 数据 (RIP-relative; 段被 packer 标记 RWX 以允许写入 slot) ----
ALIGN 8
g_table     dq 0
g_base      dq 0
p_VP        dq 0
p_Flush     dq 0
; call-gate 用完即擦: 影子栈 per-thread(TLS)。每线程一块 {sp:q; frames[128]*24}, 首次用时
; VirtualAlloc+TlsSetValue。frame = (entry_va, len, realret) = 24B。深度=栈上"不同"被保护函数数。
g_tlsidx    dd 0
p_TlsGet    dq 0
p_TlsSet    dq 0
p_VAlloc    dq 0
s_tlsa      db "TlsAlloc",0
s_tlsg      db "TlsGetValue",0
s_tlss      db "TlsSetValue",0
s_valloc    db "VirtualAlloc",0
s_gpa       db "GetProcAddress",0
s_vp        db "VirtualProtect",0
s_flush     db "FlushInstructionCache",0
s_av        db "AddVectoredExceptionHandler",0
s_exit      db "ExitProcess",0
ALIGN 8
PUBLIC g_tbl
g_tbl       LABEL BYTE                 ; 侧表落点; packer 从此处追加 [count][entries][stash]

_TEXT ENDS
END
