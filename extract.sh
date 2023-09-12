#!/bin/bash
for i in $(objdump -d DecryptProtect.exe | grep "^ " | cut -f2); do echo -e -n "\x$i"; done > decryptprotect.bin