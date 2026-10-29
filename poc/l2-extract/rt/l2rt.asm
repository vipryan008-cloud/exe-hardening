; ===========================================================================
; L2 运行时 (x64, MASM) —— 可嵌入的惰性回填引擎。
;
;   l2_install(rcx = table_ptr, rdx = image_base)
;     自解析 kernel32 API → 装 VEH → 返回。之后被抽函数首次执行(int3)时,
;     VEH 从侧表解密回填真码, 把 RIP 拨回函数入口重执行。
;
; table 布局 (packer 或测试 harness 构造):
;   +0  qword count
;   +8  count 个 entry, 每个 24 字节: { qword rva; qword len; qword stash_off }
;       stash_off = 从 table 起始到该函数密文字节的偏移
;   之后: 各函数的密文字节 (原码 xor STASH_XOR)
;
; API 用 get_proc 只自解析 GetProcAddress(非转发), 其余走 GetProcAddress(跟转发)。
; ===========================================================================

STASH_XOR   equ 0A7h
EXC_BP      equ 80000003h      ; EXCEPTION_BREAKPOINT
CONT_EXEC   equ 0FFFFFFFFh     ; EXCEPTION_CONTINUE_EXECUTION (-1)
CONT_SEARCH equ 0             ; EXCEPTION_CONTINUE_SEARCH
CTX_RIP     equ 0F8h           ; CONTEXT.Rip 偏移
PAGE_RWX    equ 40h

_DATA SEGMENT
g_table     dq 0               ; 侧表指针
g_base      dq 0               ; image base
p_VP        dq 0               ; VirtualProtect
p_Flush     dq 0               ; FlushInstructionCache
; 函数名字符串
s_gpa       db "GetProcAddress",0
s_vp        db "VirtualProtect",0
s_flush     db "FlushInstructionCache",0
s_av        db "AddVectoredExceptionHandler",0
_DATA ENDS

_TEXT SEGMENT

EXTERN get_kernel32_base:PROC
EXTERN get_proc:PROC

; ---------------------------------------------------------------------------
PUBLIC l2_install
l2_install PROC
    push    rbx
    push    rsi
    push    rdi
    sub     rsp, 20h                    ; shadow(32); 3 push + 0x20 => 调用点 16 对齐

    lea     rbx, g_table
    mov     [rbx], rcx                  ; 存 table_ptr
    lea     rsi, g_base
    mov     [rsi], rdx                  ; 存 image_base

    call    get_kernel32_base           ; rax = kernel32 base
    mov     rbx, rax                    ; rbx = base

    ; GetProcAddress (自解析)
    mov     rcx, rbx
    lea     rdx, s_gpa
    call    get_proc
    mov     rdi, rax                    ; rdi = GetProcAddress

    ; VirtualProtect = GPA(base, "VirtualProtect")
    mov     rcx, rbx
    lea     rdx, s_vp
    call    rdi
    lea     rcx, p_VP
    mov     [rcx], rax

    ; FlushInstructionCache = GPA(base, "FlushInstructionCache")
    mov     rcx, rbx
    lea     rdx, s_flush
    call    rdi
    lea     rcx, p_Flush
    mov     [rcx], rax

    ; AddVectoredExceptionHandler = GPA(base, "AddVectoredExceptionHandler")
    mov     rcx, rbx
    lea     rdx, s_av
    call    rdi                         ; rax = AddVEH (GPA 跟转发到 ntdll)
    mov     rcx, 1                      ; First = 1
    lea     rdx, l2_handler
    call    rax                         ; AddVEH(1, handler)

    add     rsp, 20h
    pop     rdi
    pop     rsi
    pop     rbx
    ret
l2_install ENDP

; ---------------------------------------------------------------------------
; LONG l2_handler(PEXCEPTION_POINTERS ep)   ; ep in rcx
; ---------------------------------------------------------------------------
PUBLIC l2_handler
l2_handler PROC
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 30h                    ; shadow(0-0x1F)+old@0x20; 7 push + 0x30 => 调用点 16 对齐

    mov     r12, rcx                    ; ep
    mov     rax, [r12]                  ; ExceptionRecord
    mov     ecx, [rax]                  ; ExceptionCode
    cmp     ecx, EXC_BP
    jne     h_pass
    mov     r13, [rax+10h]              ; 故障地址 (ExceptionAddress)

    lea     rbx, g_table
    mov     rbx, [rbx]                  ; table
    test    rbx, rbx
    jz      h_pass
    lea     rax, g_base
    mov     r14, [rax]                  ; image base
    mov     r15, [rbx]                  ; count
    lea     rsi, [rbx+8]                ; -> entry[0]
    xor     rdi, rdi                    ; i = 0
h_loop:
    cmp     rdi, r15
    jae     h_pass
    mov     rax, [rsi]                  ; rva
    add     rax, r14                    ; entry_va
    mov     rcx, [rsi+8]               ; len
    ; 命中? entry_va <= fault < entry_va+len
    cmp     r13, rax
    jb      h_nextentry
    lea     rdx, [rax+rcx]
    cmp     r13, rdx
    jae     h_nextentry
    ; --- 命中: 回填 ---
    ; 保存 entry_va(rax)/len(rcx) 到非易失寄存器
    mov     rbx, rax                    ; rbx = entry_va (覆盖 table, 已不需要)
    mov     r15, rcx                    ; r15 = len
    mov     r14, [rsi+10h]             ; stash_off
    ; stash_ptr = table + stash_off ; 但 table 已被 rbx 覆盖 → 重取
    lea     rax, g_table
    mov     rax, [rax]
    add     r14, rax                    ; r14 = stash_ptr

    ; VirtualProtect(entry_va, len, PAGE_RWX, &old)   old 放 [rsp+20h]
    mov     rcx, rbx
    mov     rdx, r15
    mov     r8d, PAGE_RWX
    lea     r9, [rsp+20h]
    lea     rax, p_VP
    call    qword ptr [rax]

    ; 解密回填: for i in len: entry[i] = stash[i] ^ STASH_XOR
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
    ; 还原保护 VirtualProtect(entry_va, len, old, &old)
    mov     rcx, rbx
    mov     rdx, r15
    mov     r8d, dword ptr [rsp+20h]
    lea     r9, [rsp+20h]
    lea     rax, p_VP
    call    qword ptr [rax]

    ; FlushInstructionCache(-1, entry_va, len)
    mov     rcx, -1
    mov     rdx, rbx
    mov     r8, r15
    lea     rax, p_Flush
    call    qword ptr [rax]

    ; ContextRecord->Rip = entry_va, 从入口重执行真码
    mov     rax, [r12+8]                ; ContextRecord
    mov     [rax+CTX_RIP], rbx
    mov     eax, CONT_EXEC
    jmp     h_done

h_nextentry:
    add     rsi, 24                     ; 下一 entry
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

_TEXT ENDS
END
