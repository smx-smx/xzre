/*
 * Copyright (C) 2024 Stefano Moioli <smxdev4@gmail.com>
 **/
#include <stdio.h>
#include <ctype.h>

void hexdump(void *address, long lSize) {
	char buffer[100];
	long len_ascii, index_hex, index_str, remaining_ascii;
	long byte_index;
	struct {
		unsigned char *data;
		unsigned long remaining;
	} buf;
	unsigned char *p, byte;

	buf.data = (unsigned char *)address;
	buf.remaining = lSize;

	while (buf.remaining > 0) {
		p = buf.data;
		len_ascii = (int)buf.remaining;
		if (len_ascii > 16)
			len_ascii = 16;

		// create a 64-character formatted output line:
		sprintf(buffer, "%08zX:                                                        ", p - (unsigned char *)address);
		remaining_ascii = len_ascii;

		static const int OFFSET_HEX = 11;
		static const int OFFSET_ASCII = (OFFSET_HEX + (9*4) + 2);

		for (index_hex = OFFSET_HEX,
			index_str = OFFSET_ASCII,
			byte_index = 0;
			remaining_ascii;
			remaining_ascii--, index_hex += 2, index_str++
		) {
			byte = *p++;
			sprintf(buffer + index_hex, "%02hhX ", byte);
			if (!isprint(byte)) {
				byte = '.';	// nonprintable char
			}
			buffer[index_str] = byte;

			if (!(++byte_index & 3)) {	// extra blank after 4 bytes
				index_hex++;
				buffer[index_hex + 2] = ' ';
			}
		}
		puts(buffer);
		buf.data += len_ascii;
		buf.remaining -= len_ascii;
	}
}
