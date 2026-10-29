; ===========================================================================
; L3 部署启动 stub (x64, MASM, PIC) —— 加壳 exe 的新入口。
; 自解析 kernel32 → LoadLibraryA("l3rt.dll") → GetProcAddress("vm_run") → 存 g_vmrun
; → jmp 原 OEP。之后各被虚拟化函数的 thunk 经 [g_vmrun 绝对VA] 调 vm_run。
; 占位: P_OEP=0x44*8 (原 OEP 绝对 VA, 固定基址)。g_vmrun 槽在 blob 内(packer 算其绝对 VA 给 thunk)。
; ===========================================================================
_TEXT SEGMENT

PUBLIC l3_entry
l3_entry PROC
    sub     rsp, 28h                    ; shadow+对齐 (入口 rsp%16==8, +0x28→对齐)
    call    get_kernel32_base
    mov     r15, rax                    ; kernel32 base
    mov     rcx, r15
    lea     rdx, s_gpa
    call    get_proc                    ; rax = GetProcAddress
    mov     rdi, rax
    mov     rcx, r15
    lea     rdx, s_ll
    call    rdi                         ; rax = LoadLibraryA
    lea     rcx, s_dll
    call    rax                         ; rax = HMODULE l3rt.dll
    mov     rcx, rax
    lea     rdx, s_vmrun
    call    rdi                         ; rax = vm_run
    lea     rcx, g_vmrun
    mov     [rcx], rax                  ; 存槽
    add     rsp, 28h
    mov     rax, 4444444444444444h      ; P_OEP (packer patch 绝对 VA)
    jmp     rax
l3_entry ENDP

; ---- 自解析 (同 resolve.asm) ----
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

get_proc PROC
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

ALIGN 8
PUBLIC g_vmrun
g_vmrun     dq 0
s_gpa       db "GetProcAddress",0
s_ll        db "LoadLibraryA",0
s_dll       db "l3rt.dll",0
s_vmrun     db "vm_run",0

_TEXT ENDS
END
