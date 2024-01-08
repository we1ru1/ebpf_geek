//
// Created by 魏锐 on 2023/12/27.
//
#include <stdio.h>
#include "head.h"

int main(){
    int a = 10, b = 5;
    printf("a + b = %d\n", add(a, b));
    printf("a - b = %d\n", sub(a, b));
    printf("a * b = %d\n", multiply(a, b));
    printf("a / b = %lf\n", divide(a, b));
    return 0;
}
