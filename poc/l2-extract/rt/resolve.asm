; ===========================================================================
; 自解析 API (PIC, x64, MASM) —— 自包含运行时注入的基石。
;   get_kernel32_base()      -> rax = kernel32.dll 基址 (PEB 走模块表, ror13 哈希匹配)
;   get_proc(rcx=base, rdx=asciiz name) -> rax = 导出函数 VA (解析导出表), 找不到=0
; 无数据段引用、无导入 => 天然 position-independent, 可作 shellcode 嵌入。
; ===========================================================================
_TEXT SEGMENT

PUBLIC get_kernel32_base
get_kernel32_base PROC
    mov     rax, gs:[60h]              ; PEB
    mov     rax, [rax+18h]             ; PEB.Ldr
    lea     rdx, [rax+10h]             ; &InLoadOrderModuleList (链表头)
    mov     rcx, [rdx]                 ; cur = 首个 Flink
gk_walk:
    cmp     rcx, rdx
    je      gk_none
    movzx   r8, word ptr [rcx+58h]     ; BaseDllName.Length (字节数)
    mov     r9, [rcx+60h]              ; BaseDllName.Buffer (UTF-16)
    xor     eax, eax                   ; hash = 0
    xor     r10, r10                   ; i = 0
gk_hash:
    cmp     r10, r8
    jae     gk_test
    movzx   r11d, byte ptr [r9+r10]    ; 逐字节
    cmp     r11b, 61h                  ; 'a'
    jb      gk_noup
    cmp     r11b, 7Ah                  ; 'z'
    ja      gk_noup
    sub     r11b, 20h                  ; 转大写
gk_noup:
    ror     eax, 13
    add     eax, r11d
    inc     r10
    jmp     gk_hash
gk_test:
    cmp     eax, 6A4ABC5Bh             ; hash("KERNEL32.DLL")
    jne     gk_next
    mov     rax, [rcx+30h]             ; LDR_DATA_TABLE_ENTRY.DllBase
    ret
gk_next:
    mov     rcx, [rcx]                 ; 下一个 Flink
    jmp     gk_walk
gk_none:
    xor     eax, eax
    ret
get_kernel32_base ENDP

PUBLIC get_proc
get_proc PROC
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    mov     rbx, rcx                   ; base
    mov     rsi, rdx                   ; wanted name
    mov     eax, [rbx+3Ch]             ; e_lfanew
    lea     r12, [rbx+rax]             ; nt header
    mov     eax, [r12+88h]             ; DataDirectory[0].VirtualAddress (export)
    test    eax, eax
    jz      gp_fail
    lea     r13, [rbx+rax]             ; export directory
    mov     r14d, [r13+18h]            ; NumberOfNames
    mov     r8d, [r13+20h]             ; AddressOfNames RVA
    lea     r8, [rbx+r8]               ; -> AddressOfNames 表
    xor     r9, r9                     ; i = 0
gp_loop:
    cmp     r9, r14
    jae     gp_fail
    mov     eax, [r8+r9*4]             ; nameRVA[i]
    lea     rdi, [rbx+rax]             ; namePtr
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
    mov     eax, [r13+24h]             ; AddressOfNameOrdinals RVA
    lea     rax, [rbx+rax]
    movzx   eax, word ptr [rax+r9*2]   ; ordinal = ordinals[i]
    mov     ecx, [r13+1Ch]             ; AddressOfFunctions RVA
    lea     rcx, [rbx+rcx]
    mov     eax, [rcx+rax*4]           ; funcRVA[ordinal]
    lea     rax, [rbx+rax]             ; -> 函数 VA
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

_TEXT ENDS
END
