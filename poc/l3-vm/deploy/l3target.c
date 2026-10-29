/* L3 部署验证靶子: secret() 被虚拟化(优化成纯寄存器算术, 可翻译)。
 * 注意: 用 __declspec(noinline) 但【不要】用 #pragma optimize off
 * (否则 secret 会把参数存栈 mov[rsp],edx = 内存写, 当前 VM 不支持)。*/
#include <stdio.h>
__declspec(noinline) int secret(int a, int b) { return a * a + b * 3 - 7; }
int main(int argc, char **argv) {
    int x = argc > 1 ? argv[1][0] : 5;
    int r = secret(x, 4);
    printf("l3target: secret(%d,4) = %d\n", x, r);
    return r;
}
