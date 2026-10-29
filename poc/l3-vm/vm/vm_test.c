/* L3 对拍: 同一函数 原生 f() vs VM(翻译后字节码) —— 全输入结果必须一致。*/
#include <stdio.h>
#include "f_bc.h"           /* translate.py 生成: f_bc[] */

extern int vm_run(const unsigned char *bc, int a, int b);

/* 原生实现 (真值 oracle) —— 必须与 f.c 里的 f() 完全一致 */
int f(int a, int b) { return a * a + b * 3 - 7; }

int main(void) {
    unsigned st = 0x12345678;
    int fails = 0, total = 0;
    /* 边界 + 伪随机扫 */
    int edge[] = {0, 1, -1, 2, -2, 100, -100, 5, 4, 32767, -32768};
    for (int i = 0; i < (int)(sizeof(edge)/sizeof(int)); i++)
        for (int j = 0; j < (int)(sizeof(edge)/sizeof(int)); j++) {
            int a = edge[i], b = edge[j];
            int nv = f(a, b), vv = vm_run(f_bc, a, b);
            total++; if (nv != vv) { fails++; if (fails<=5) printf("  MISMATCH f(%d,%d): native=%d vm=%d\n",a,b,nv,vv); }
        }
    for (int k = 0; k < 20000; k++) {
        st = st * 1103515245u + 12345u; int a = (int)st;
        st = st * 1103515245u + 12345u; int b = (int)st;
        int nv = f(a, b), vv = vm_run(f_bc, a, b);
        total++; if (nv != vv) { fails++; if (fails<=5) printf("  MISMATCH f(%d,%d): native=%d vm=%d\n",a,b,nv,vv); }
    }
    printf("L3 VM 对拍: %d 用例, %d 失配  => %s\n", total, fails, fails==0 ? "PASS (VM==原生)" : "FAIL");
    return fails == 0 ? 0 : 1;
}
