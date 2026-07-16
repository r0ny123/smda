#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

__declspec(noinline) int c_leaf(int value) {
    return value * 3 + 1;
}

__declspec(noinline) int c_stack(int seed) {
    volatile unsigned char buffer[768];
    int value = seed;
    for (size_t index = 0; index < sizeof(buffer); index++) {
        buffer[index] = (unsigned char)(value + index);
        value += buffer[index];
    }
    return value;
}

__declspec(noinline) int c_variadic(int count, ...) {
    va_list values;
    int total = 0;
    va_start(values, count);
    for (int index = 0; index < count; index++) {
        total += va_arg(values, int);
    }
    va_end(values);
    return total;
}

__declspec(noinline) int c_indirect(int (*callback)(int), int value) {
    return callback(value) + 7;
}

int main(void) {
    return c_indirect(c_leaf, c_stack(3)) + c_variadic(4, 1, 2, 3, 4);
}
