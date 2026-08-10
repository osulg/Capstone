/* test_c_medium.c
 * 최소한의 시스템콜만 사용해서 동적 모델 점수를 낮게 유도
 * 컴파일: gcc -o test_c_medium test_c_medium.c
 * 실행:   ./test_c_medium ~/test_mount/honeypot/c_trap.txt
 */
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <path>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "w");
    if (!f) {
        perror("fopen");
        return 1;
    }

    /* 딱 한 번 write — O_sum=1, C_sum=1, E_sum=0, 3-gram 없음 */
    const char *msg = "minimal write from C binary\n";
    fwrite(msg, 1, strlen(msg), f);
    fclose(f);

    return 0;
}
