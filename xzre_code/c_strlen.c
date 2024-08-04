/**
 * Copyright (C) 2024 Koen Van Bastelaere <koen@datix.be>
 **/
#include "xzre.h"

ssize_t c_strlen(char *str) {
    if (*str != '\0') {
        ssize_t len = 0;
        do {
            ++len;
        } while (*(str + len) != '\0');
        return len;
    }
    return 0;
}
