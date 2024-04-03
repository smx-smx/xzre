# xzre
Reverse engineering of the XZ backdoor

The goal of this project is to document the functions, data structures and inner working of the XZ backdoor malware, with the goal of understanding how it works, understanding the tricks used, and serve as a reference for other analyses.

**NOTE**: this repository includes a copy of the original `liblzma_la-crc64-fast.o` found in liblzma 5.6.1

This project builds a binary, `xzre`, that is linked against the malicious object file in order to instrument and call into the malware code, particularly the x64 disassembler.

Although no side effects have been observed, it's recommended to run this code only in a sandbox/virtual machine until the full code has been understood.
