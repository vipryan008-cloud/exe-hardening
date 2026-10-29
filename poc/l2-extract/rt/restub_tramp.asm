; ===========================================================================
; 用完即擦 (call-gate) 返回蹦床 (x64, MASM)。
;
; 被保护函数首次执行(int3)时 VEH 回填真码, 并把其"返回地址"改成本蹦床地址、
; 把 (函数,真返回地址,长度) 压入影子栈。函数 ret 时落到这里:
;   保存返回值(rax/rdx) → 调 restub_pop(弹栈+把该函数重新抽成int3, 返回真返回地址)
;   → 恢复返回值 → jmp 真返回地址。
; => 任意时刻只有"正在栈上执行"的被保护函数是明文, 返回即擦回 int3 (抗主动dump)。
; ===========================================================================
_TEXT SEGMENT
EXTERN restub_pop:PROC              ; void* restub_pop(void)  返回真返回地址

PUBLIC restub_tramp
restub_tramp PROC
    push    rax                    ; 保存整型返回值
    push    rdx
    sub     rsp, 20h               ; shadow(32); 2 push + 0x20 => 调用点 16 对齐
    call    restub_pop             ; rax = 真返回地址 (并已重抽该函数)
    mov     r11, rax
    add     rsp, 20h
    pop     rdx
    pop     rax                    ; 恢复返回值
    jmp     r11                    ; 回到真正的调用者
restub_tramp ENDP
_TEXT ENDS
END
