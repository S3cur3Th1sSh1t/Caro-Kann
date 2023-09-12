# Caro Kann

<p align="center">
<img src="https://github.com/S3cur3Th1sSh1t/Caro-Kann/blob/main/images/CaroKann.jpg?raw=true" alt="Caro Kann defense" width="400" height="400">
</p>

Encrypted shellcode Injection to avoid memory scans triggered from Kernel (ETWti / Kernel Callbacks). Specific combinations of Windows APIs, e.g. for injection into a remote process can lead to a memory scan:

<p align="center">
<img src="https://github.com/S3cur3Th1sSh1t/Caro-Kann/blob/main/images/ScanTrigger.png?raw=true" alt="ScanTrigger">
</p>

Typically, the scan can be triggered from Userland via hooks on the execute primitive such as `NtCreateThreadEx`. But more and more EDR vendors also tend to trigger scans from Kernel, for example after the Kernel Callback `PsSetCreateThreadNotifyRoutine()` a scan could be triggered. But what if there is no executable memory section with known malicious code? Well, no alert for an detection I guess.

<ins>The idea is as follows:</ins>

- Inject encrypted <ins>known malicious</ins> payload into an `RW` section
- Inject custom non <ins>known malicious</ins> shellcode into an `RX` section
- Create a remote Thread on the second shellcode

<p align="center">
<img src="https://github.com/S3cur3Th1sSh1t/Caro-Kann/blob/main/images/Inject.png?raw=true" alt="Inject">
</p>

<ins>The custom shellcode will than:</ins>

- Sleep for an amount x (to avoid memory scans triggered by the execute primitive of Thread creation)
- Decrypt the first <ins>known malicious</ins> shellcode
- Protect the section from `RW` to `RX`
- Make a direct `JMP` to the known malicious shellcode

<p align="center">
<img src="https://github.com/S3cur3Th1sSh1t/Caro-Kann/blob/main/images/Shellcode.png?raw=true" alt="Shellcode">
</p>

## Setup

On linux, the PIC-Code was found to be compiled correctly with `mingw-w64` version `version 10-win32 20220324 (GCC)`. With that version installed, the shellcode can be compiled with a simple `make` and extracted from the `.text` section via `bash extract.sh`. 

If you'd like to compile from Windows, you can use the following commands:

```
as -o adjuststack.o adjuststack_as.asm
gcc ApiResolve.c -Wall -m64 -ffunction-sections -fno-asynchronous-unwind-tables -nostdlib -fno-ident -O2 -c -o ApiResolve.o -Wl,--no-seh
gcc DecryptProtect.c -Wall -m64 -masm=intel -ffunction-sections -fno-asynchronous-unwind-tables -nostdlib -fno-ident -O2 -c -o decryptprotect.o -Wl,--no-seh
ld -s adjuststack.o ApiResolve.o decryptprotect.o -o decryptprotect.exe
gcc extract.c -o extract.exe
extract.exe
```

You also need to have [Nim](https://nim-lang.org/) installed for this PoC.

<ins>After installation, the dependencies can be installed via the following oneliner:</ins>

```nim
nimble install winim ptr_math
```

<ins>The PoC can than be compiled with:</ins>

```nim
nim c -d:release -d=mingw -d:noRes CaroKann.nim # Cross compile
nim c -d:release CaroKann.nim # Windows
```

Any payload can be XOR encrypted with the given `encrypt.cpp` code:

```
Usage: encrypter.exe input_file output_file
```

The encrypted payload can than be embedded in the PoC via the following line:

```
const shellcode = slurp"<encrypted.bin>"
```


## OPSec improvement ideas

- Bypass Userland-Hooks for Injection (although not really needed, but for fun)
- Back Payload(s) by legitimate DLL (Module Stomping)
- Load C2-Dlls via the first Shellcode - which can avoid memory scans triggered by module loads
- Use ThreadlessInject or DLLNotificationInjection instead of Remote Thread Creation

## OPSec considerations for C2-Payloads

- Should use Sleep encryption, otherwise the payload will get flagged later
- Should use Unhooking first or (in)direct Syscalls
- Should use Proxy module loading
