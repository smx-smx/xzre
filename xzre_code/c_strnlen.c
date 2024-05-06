/**
 * Copyright (C) 2024 Koen Van Bastelaere <koen@datix.be>
 **/
#include "xzre.h"

ssize_t c_strnlen(char *str, size_t max_len) {
    ssize_t len = 0;
    if (max_len == 0)
        return max_len;
    do {
        if (*(str + len) == '\0')
            return len;
        ++len;
    } while (max_len != len);
    return max_len;
}
