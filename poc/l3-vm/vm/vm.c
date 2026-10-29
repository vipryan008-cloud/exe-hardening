/* ==========================================================================
 * L3 代码虚拟化 —— 寄存器式 VM 解释器 (x64 语义子集, 32-bit int)。
 *
 * 被虚拟化的函数不再有原生 x86, 只剩本 VM 的字节码 + 派发循环。翻译器
 * (translate.py) 把选定函数的 x86 算术指令编译成这套字节码。
 *
 * 16 个虚拟寄存器映射 x86 GPR (eax=0 ecx=1 edx=2 ebx=3 ...)。入口按 x64 fastcall
 * 载入前两个 int 参数到 ecx/edx。当前子集: MOV/MOVI/ADD/SUB/IMUL/IMULI/ADDI/
 * XOR/AND/OR/SHLI/SHRI/LEA/RET (足够覆盖编译器对算术表达式的常见 lea/imul 生成)。
 * ========================================================================== */
#include <stdint.h>

enum {
    OP_MOV = 1, OP_MOVI, OP_ADD, OP_SUB, OP_IMUL, OP_IMULI, OP_ADDI,
    OP_XOR, OP_AND, OP_OR, OP_SHLI, OP_SHRI, OP_LEA,
    OP_CMP, OP_CMPI, OP_TEST, OP_JMP, OP_JCC,     /* Gate3 控制流 */
    OP_SUBI, OP_ANDI, OP_ORI, OP_XORI,            /* imm 版 ALU */
    OP_CMOV,                                      /* 条件移动 */
    OP_NEG, OP_NOT, OP_SARI,                      /* 一元 + 算术右移(立即) */
    OP_SHL, OP_SHR, OP_SAR,                       /* 变量移位(移位量在寄存器低字节) */
    OP_MOVZX, OP_MOVSX,                           /* 子寄存器零/符号扩展 (size=1/2 字节) */
    OP_RET = 0xFF
};
/* JCC/CMOV 条件码 */
enum { CC_E, CC_NE, CC_L, CC_GE, CC_G, CC_LE, CC_B, CC_AE, CC_A, CC_BE };

static __forceinline int cc_take(int cc, uint32_t va, uint32_t vb)
{
    switch (cc) {
    case CC_E:  return va == vb;
    case CC_NE: return va != vb;
    case CC_L:  return (int32_t)va <  (int32_t)vb;
    case CC_GE: return (int32_t)va >= (int32_t)vb;
    case CC_G:  return (int32_t)va >  (int32_t)vb;
    case CC_LE: return (int32_t)va <= (int32_t)vb;
    case CC_B:  return va <  vb;
    case CC_AE: return va >= vb;
    case CC_A:  return va >  vb;
    case CC_BE: return va <= vb;
    }
    return 0;
}

/* bytecode 编码 (小端):
 *   MOV/ADD/SUB/IMUL/XOR/AND/OR: op, (rd<<4|rs)
 *   MOVI/IMULI/ADDI:            op, rd, imm32
 *   SHLI/SHRI:                  op, rd, imm8
 *   LEA:                        op, rd, base, index, scale, disp32   (base/index=0xFF 表示无)
 *   RET:                        op, rs
 *   CMP/TEST:                   op, (rd<<4|rs)          存比较操作数 va,vb
 *   CMPI:                       op, rd, imm32
 *   JMP:                        op, u16 目标(字节码偏移)
 *   JCC:                        op, cc, u16 目标
 * 条件判定用"存比较操作数"(va,vb)而非全 flags 模拟: CMP→va=a,vb=b; TEST→va=a&b,vb=0。
 * 对 E/NE/L/GE/G/LE(有符号) 与 B/AE/A/BE(无符号) 语义正确(cmp 与 test 均适用)。
 */
int32_t vm_run(const uint8_t *bc, int a, int b)
{
    uint32_t r[16] = {0};
    uint32_t va = 0, vb = 0;            /* 上次比较操作数 */
    r[1] = (uint32_t)a;                 /* ecx = arg0 */
    r[2] = (uint32_t)b;                 /* edx = arg1 */
    const uint8_t *p = bc;
    /* 用 if/else 阶梯而非 switch: 避免编译器生成绝对地址跳转表, 使 vm_run 成为
       position-independent(无重定位), 可作 PIC blob 嵌入加固 exe(见 harden_l3.py)。*/
    for (;;) {
        uint8_t op = *p++;
        /* MOV/MOVI/LEA 不影响 flags; 其余 ALU 设 va=结果,vb=0 (模型 ZF/SF 及 vs0 的有符号/无符号比较) */
        if      (op==OP_MOV)  { uint8_t x=*p++; r[x>>4]=r[x&15]; }
        else if (op==OP_MOVI) { uint8_t d=*p++; uint32_t i=*(uint32_t*)p; p+=4; r[d]=i; }
        else if (op==OP_LEA)  { uint8_t d=*p++, base=*p++, idx=*p++, scale=*p++;
                                int32_t disp=*(int32_t*)p; p+=4;
                                r[d]=(base==0xFF?0:r[base])+(idx==0xFF?0:r[idx]*scale)+(uint32_t)disp; }
        else if (op==OP_ADD)  { uint8_t x=*p++,d=x>>4; r[d]+=r[x&15]; va=r[d]; vb=0; }
        else if (op==OP_SUB)  { uint8_t x=*p++,d=x>>4; r[d]-=r[x&15]; va=r[d]; vb=0; }
        else if (op==OP_IMUL) { uint8_t x=*p++,d=x>>4; r[d]*=r[x&15]; va=r[d]; vb=0; }
        else if (op==OP_XOR)  { uint8_t x=*p++,d=x>>4; r[d]^=r[x&15]; va=r[d]; vb=0; }
        else if (op==OP_AND)  { uint8_t x=*p++,d=x>>4; r[d]&=r[x&15]; va=r[d]; vb=0; }
        else if (op==OP_OR)   { uint8_t x=*p++,d=x>>4; r[d]|=r[x&15]; va=r[d]; vb=0; }
        else if (op==OP_IMULI){ uint8_t d=*p++; int32_t i=*(int32_t*)p; p+=4; r[d]=(uint32_t)((int32_t)r[d]*i); va=r[d]; vb=0; }
        else if (op==OP_ADDI) { uint8_t d=*p++; int32_t i=*(int32_t*)p; p+=4; r[d]+=(uint32_t)i; va=r[d]; vb=0; }
        else if (op==OP_SUBI) { uint8_t d=*p++; int32_t i=*(int32_t*)p; p+=4; r[d]-=(uint32_t)i; va=r[d]; vb=0; }
        else if (op==OP_ANDI) { uint8_t d=*p++; uint32_t i=*(uint32_t*)p; p+=4; r[d]&=i; va=r[d]; vb=0; }
        else if (op==OP_ORI)  { uint8_t d=*p++; uint32_t i=*(uint32_t*)p; p+=4; r[d]|=i; va=r[d]; vb=0; }
        else if (op==OP_XORI) { uint8_t d=*p++; uint32_t i=*(uint32_t*)p; p+=4; r[d]^=i; va=r[d]; vb=0; }
        else if (op==OP_SHLI) { uint8_t d=*p++,i=*p++; r[d]<<=i; va=r[d]; vb=0; }
        else if (op==OP_SHRI) { uint8_t d=*p++,i=*p++; r[d]>>=i; va=r[d]; vb=0; }
        else if (op==OP_SARI) { uint8_t d=*p++,i=*p++; r[d]=(uint32_t)((int32_t)r[d]>>i); va=r[d]; vb=0; }
        else if (op==OP_NEG)  { uint8_t d=*p++; r[d]=(uint32_t)(-(int32_t)r[d]); va=r[d]; vb=0; }
        else if (op==OP_NOT)  { uint8_t d=*p++; r[d]=~r[d]; }   /* not 不影响 flags */
        else if (op==OP_SHL)  { uint8_t x=*p++,d=x>>4; r[d]<<=(r[x&15]&31); va=r[d]; vb=0; }
        else if (op==OP_SHR)  { uint8_t x=*p++,d=x>>4; r[d]>>=(r[x&15]&31); va=r[d]; vb=0; }
        else if (op==OP_SAR)  { uint8_t x=*p++,d=x>>4; r[d]=(uint32_t)((int32_t)r[d]>>(r[x&15]&31)); va=r[d]; vb=0; }
        else if (op==OP_MOVZX){ uint8_t x=*p++,sz=*p++,d=x>>4; uint32_t m=(sz==1)?0xFF:0xFFFF; r[d]=r[x&15]&m; }
        else if (op==OP_MOVSX){ uint8_t x=*p++,sz=*p++,d=x>>4;
                                r[d]=(sz==1)?(uint32_t)(int32_t)(int8_t)r[x&15]:(uint32_t)(int32_t)(int16_t)r[x&15]; }
        else if (op==OP_CMP)  { uint8_t x=*p++; va=r[x>>4]; vb=r[x&15]; }
        else if (op==OP_CMPI) { uint8_t d=*p++; uint32_t i=*(uint32_t*)p; p+=4; va=r[d]; vb=i; }
        else if (op==OP_TEST) { uint8_t x=*p++; va=r[x>>4]&r[x&15]; vb=0; }
        else if (op==OP_JMP)  { uint16_t t=*(uint16_t*)p; p=bc+t; }
        else if (op==OP_JCC)  { uint8_t cc=*p++; uint16_t t=*(uint16_t*)p; p+=2; if(cc_take(cc,va,vb)) p=bc+t; }
        else if (op==OP_CMOV) { uint8_t cc=*p++,x=*p++; if(cc_take(cc,va,vb)) r[x>>4]=r[x&15]; }
        else if (op==OP_RET)  { uint8_t s=*p++; return (int32_t)r[s]; }
        else return -0x0BADC0DE;    /* 未知 opcode */
    }
}
