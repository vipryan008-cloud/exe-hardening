/* L1 加壳验证靶子: 有输出/循环/API调用/读argv, 便于比对加壳前后行为一致。*/
#include <stdio.h>
#include <windows.h>

int main(int argc, char **argv)
{
    printf("sample: start\n");
    printf("sample: module base = %p\n", (void *)GetModuleHandleW(NULL));

    long sum = 0;
    for (int i = 1; i <= 100; i++) sum += i;
    printf("sample: sum(1..100) = %ld\n", sum);   /* 期望 5050 */

    DWORD pid = GetCurrentProcessId();             /* 真调 kernel32 API */
    printf("sample: pid nonzero = %d\n", pid != 0);

    printf("sample: argc = %d\n", argc);
    if (argc > 1) printf("sample: arg1 = %s\n", argv[1]);

    printf("sample: done\n");
    return 7;
}
