/**
 * Copyright (C) 2024 Koen Van Bastelaere <koen@datix.be>
 **/
#include "xzre.h"

void c_memmove(char *dest, char *src, size_t cnt) {
    if ((src < dest) && (dest < (src + cnt))) {
        size_t curr = cnt - 1;
        if (cnt != 0) {
            do {
                *(dest + curr) = *(src + curr);
                --curr;
            } while (curr != -1);
            return;
        }
    } else {
        if (cnt == 0)
            return;
        size_t curr = 0;
        do {
            *(dest + curr) = *(src + curr);
            ++curr;
        } while (cnt != curr);
    }
    return;
}
