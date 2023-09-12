#pragma once

#include <stdint.h>
#include "windows.h"


uint64_t getFunctionPtr(unsigned long, unsigned long);

// Everything but ntdll.dll functions/typedefs/Hashes is not needed for the PoC. I know. 
// But for me the idea is funny, that AV/EDR vendors could build Shellcode Signatures for that code or hashes, and they are bypassable by just removing it.
// So I left everything as it is just for the sake of fun and lazyness. :-)

// ----  KERNEL32 ----
#define HASH_KERNEL32 0x7040ee75 
#define HASH_LOADLIBRARYA 0x5fbff0fb
#define HASH_GETPROCADDRESS 0xcf31bb1f
#define HASH_OPENPROCESS 0x7136fdd6
#define HASH_GETFINALPATHNAMEBYHANDLEA 0x92389065
#define HASH_VIRTUALPROTECT 0x844ff18d
#define HASH_GETCURRENTPROCESSID 0xa3bf64b4
#define HASH_LSTRCMPIA 0x2abba0b4
#define HASH_OUTPUTDEBUGSTRINGA 0x79729f95
#define HASH_SLEEP 0xe19e5fe


typedef HMODULE(WINAPI* LOADLIBRARYA)(LPCSTR);
typedef FARPROC(WINAPI* GETPROCADDRESS)(HMODULE, LPCSTR);
typedef BOOL(WINAPI* VIRTUALPROTECT)(_In_ LPVOID, _In_ SIZE_T, _In_ DWORD, _Out_ PDWORD);
typedef BOOL(WINAPI* GETFINALPATHNAMEBYHANDLEA)(_In_ HANDLE, _Out_ LPSTR, _In_ DWORD, _In_ DWORD);
typedef BOOL(WINAPI* OPENPROCESS)(_In_ DWORD, _In_ BOOL, _In_ DWORD);
typedef BOOL(WINAPI* GETCURRENTPROCESSID)();
typedef int(WINAPI* LSTRCMPIA)(_In_ LPCSTR, _In_ LPCSTR);
typedef void(WINAPI* OUTPUTDEBUGSTRINGA)(_In_ LPCSTR);
typedef DWORD(WINAPI* GETTICKCOUNT)();
typedef VOID(WINAPI* SLEEP)(_In_ DWORD);

#define HASH_GETTICKCOUNT 0x41ad16b9

// ---- Shlwapi ----

#define HASH_SHLWAPI 0xa70d9427
#define HASH_STRSTRIA 0x67a6a81

typedef int(WINAPI* STRSTRIA)(_In_ LPCSTR, _In_ LPCSTR);

// ---- NTDLL ----


typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;


typedef struct _OBJECT_ATTRIBUTES
{
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES;

typedef OBJECT_ATTRIBUTES* POBJECT_ATTRIBUTES;

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID    Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef struct _FILE_NAME_INFORMATION {
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_NAME_INFORMATION, * PFILE_NAME_INFORMATION;

typedef enum _FILE_INFORMATION_CLASS {
    FileDirectoryInformation = 1,
    FileFullDirectoryInformation,                   // 2
    FileBothDirectoryInformation,                   // 3
    FileBasicInformation,                           // 4
    FileStandardInformation,                        // 5
    FileInternalInformation,                        // 6
    FileEaInformation,                              // 7
    FileAccessInformation,                          // 8
    FileNameInformation,                            // 9
    FileRenameInformation,                          // 10
    FileLinkInformation,                            // 11
    FileNamesInformation,                           // 12
    FileDispositionInformation,                     // 13
    FilePositionInformation,                        // 14
    FileFullEaInformation,                          // 15
    FileModeInformation,                            // 16
    FileAlignmentInformation,                       // 17
    FileAllInformation,                             // 18
    FileAllocationInformation,                      // 19
    FileEndOfFileInformation,                       // 20
    FileAlternateNameInformation,                   // 21
    FileStreamInformation,                          // 22
    FilePipeInformation,                            // 23
    FilePipeLocalInformation,                       // 24
    FilePipeRemoteInformation,                      // 25
    FileMailslotQueryInformation,                   // 26
    FileMailslotSetInformation,                     // 27
    FileCompressionInformation,                     // 28
    FileObjectIdInformation,                        // 29
    FileCompletionInformation,                      // 30
    FileMoveClusterInformation,                     // 31
    FileQuotaInformation,                           // 32
    FileReparsePointInformation,                    // 33
    FileNetworkOpenInformation,                     // 34
    FileAttributeTagInformation,                    // 35
    FileTrackingInformation,                        // 36
    FileIdBothDirectoryInformation,                 // 37
    FileIdFullDirectoryInformation,                 // 38
    FileValidDataLengthInformation,                 // 39
    FileShortNameInformation,                       // 40
    FileIoCompletionNotificationInformation,        // 41
    FileIoStatusBlockRangeInformation,              // 42
    FileIoPriorityHintInformation,                  // 43
    FileSfioReserveInformation,                     // 44
    FileSfioVolumeInformation,                      // 45
    FileHardLinkInformation,                        // 46
    FileProcessIdsUsingFileInformation,             // 47
    FileNormalizedNameInformation,                  // 48
    FileNetworkPhysicalNameInformation,             // 49
    FileIdGlobalTxDirectoryInformation,             // 50
    FileIsRemoteDeviceInformation,                  // 51
    FileUnusedInformation,                          // 52
    FileNumaNodeInformation,                        // 53
    FileStandardLinkInformation,                    // 54
    FileRemoteProtocolInformation,                  // 55

    //
    //  These are special versions of these operations (defined earlier)
    //  which can be used by kernel mode drivers only to bypass security
    //  access checks for Rename and HardLink operations.  These operations
    //  are only recognized by the IOManager, a file system should never
    //  receive these.
    //

    FileRenameInformationBypassAccessCheck,         // 56
    FileLinkInformationBypassAccessCheck,           // 57

    //
    // End of special information classes reserved for IOManager.
    //

    FileVolumeNameInformation,                      // 58
    FileIdInformation,                              // 59
    FileIdExtdDirectoryInformation,                 // 60
    FileReplaceCompletionInformation,               // 61
    FileHardLinkFullIdInformation,                  // 62
    FileIdExtdBothDirectoryInformation,             // 63
    FileDispositionInformationEx,                   // 64
    FileRenameInformationEx,                        // 65
    FileRenameInformationExBypassAccessCheck,       // 66
    FileDesiredStorageClassInformation,             // 67
    FileStatInformation,                            // 68
    FileMemoryPartitionInformation,                 // 69
    FileStatLxInformation,                          // 70
    FileCaseSensitiveInformation,                   // 71
    FileLinkInformationEx,                          // 72
    FileLinkInformationExBypassAccessCheck,         // 73
    FileStorageReserveIdInformation,                // 74
    FileCaseSensitiveInformationForceAccessCheck,   // 75
    FileKnownFolderInformation,   // 76

    FileMaximumInformation
} FILE_INFORMATION_CLASS, * PFILE_INFORMATION_CLASS;


// PIO_APC_ROUTINE
typedef VOID(NTAPI* PIO_APC_ROUTINE)(
	_In_ PVOID ApcContext,
	_In_ PIO_STATUS_BLOCK IoStatusBlock,
	_In_ ULONG Reserved
	);

// PIO_APC_ROUTINE
typedef VOID(NTAPI* PIO_APC_ROUTINE)(
	_In_ PVOID ApcContext,
	_In_ PIO_STATUS_BLOCK IoStatusBlock,
	_In_ ULONG Reserved
	);

// PANSI_STRING
typedef struct _ANSI_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PSTR Buffer;
} ANSI_STRING, * PANSI_STRING;

// PCSZ
typedef const char* PCSZ;

#define HASH_NTDLL 0x22d3b5ed
#define HASH_NTMAPVIEWOFSECTION 0x231f196a
#define HASH_NTCREATESECTION 0xd02e20d0
#define HASH_RTLINITUNICODESTRING 0x29b75f89
#define HASH_LDRLOADDLL 0x307db23
#define HASH_NTPROTECTVIRTUALMEMORY 0x82962c8
#define HASH_NTQUERYINFORMATIONFILE 0x4725f863
#define HASH_DBGPRINT 0xab26693f
#define HASH_NTCREATEFILE 0x15a5ecdb
#define HASH_NTWRITEFILE 0xd69326b2
#define HASH_NTCLOSE 0x8b8e133d
#define HASH_RTLINITUNICODESTRING 0x29b75f89
#define HASH_RTLINITANSISTRING 0xffa3b90d
#define HASH_INITIALIZEOBJECTATTRIBUTES 0xb446ffb5
#define HASH_RTLANSISTRINGTOUNICODESTRING 0xaadebf7a
#define HASH_RTLUNICODETOMULTIBYTEN 0xfe4ae70e

typedef NTSTATUS(WINAPI* myNtCreateSection)(PHANDLE SectionHandle,ACCESS_MASK DesiredAccess,POBJECT_ATTRIBUTES ObjectAttributes,PLARGE_INTEGER MaximumSize,ULONG SectionPageProtection,ULONG AllocationAttributes, HANDLE FileHandle); //define NtCreateSection
typedef NTSTATUS(WINAPI* NTCREATESECTION)(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle); //define NtCreateSection
typedef NTSTATUS(WINAPI* LDRLOADDLL)(PWCHAR PathToFile, ULONG Flags, PUNICODE_STRING ModuleFileName, PHANDLE ModuleHandle); //define LdrLoadDll
typedef NTSTATUS(WINAPI* RTLINITUNICODESTRING)(PUNICODE_STRING DestinationString, PCWSTR SourceString); //define RtlInitUnicodeString
typedef NTSTATUS(WINAPI* NTPROTECTVIRTUALMEMORY)(HANDLE ProcessHandle, PVOID* BaseAddress, PULONG NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection); //define NtProtectVirtualMemory
typedef NTSTATUS(WINAPI* NTQUERYINFORMATIONFILE)(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass); //define NtQueryInformationFile
typedef NTSTATUS(WINAPI* DBGPRINT)(PCCH Format); //define DbgPrint
typedef NTSTATUS(WINAPI* NTCREATEFILE)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength); //define NtCreateFile
typedef NTSTATUS(WINAPI* NTWRITEFILE)(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key); //define NtWriteFile
typedef NTSTATUS(WINAPI* NTCLOSE)(HANDLE Handle); //define NtClose
typedef NTSTATUS(WINAPI* RTLANSISTRINGTOUNICODESTRING)(PUNICODE_STRING DestinationString, PANSI_STRING SourceString, BOOLEAN AllocateDestinationString); //define RtlAnsiStringToUnicodeString
typedef NTSTATUS(WINAPI* INITIALIZEOBJECTATTRIBUTES)(POBJECT_ATTRIBUTES p, PUNICODE_STRING n, ULONG a, HANDLE r, PSECURITY_DESCRIPTOR s); //define InitializeObjectAttributes
typedef NTSTATUS(WINAPI* RTLINITANSISTRING)(PANSI_STRING DestinationString, PCSZ SourceString); //define RtlInitAnsiString
typedef NTSTATUS(WINAPI* RTLINITUNICODESTRING)(PUNICODE_STRING DestinationString, PCWSTR SourceString); //define RtlInitUnicodeString
typedef NTSTATUS(WINAPI* RTLUNICODETOMULTIBYTEN)(PCHAR MultiByteString, ULONG MaxBytesInMultiByteString, PULONG BytesInMultiByteString, PCWCH UnicodeString, ULONG BytesInUnicodeString); //define RtlUnicodeToMultiByteN


// ---- USER32 ----
#define HASH_USER32 0x5a6bd3f3
#define HASH_MESSAGEBOXA 0x384f14b4

typedef int(WINAPI* MESSAGEBOXA)(HWND, LPCSTR, LPCSTR, UINT);


typedef PCSTR(WINAPI* STRSTRA)(PCSTR, PCSTR);

typedef struct _UNICODE_STR {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR pBuffer;
} UNICODE_STR, * PUNICODE_STR;

typedef struct _PEB_LDR_DATA
{
    DWORD dwLength;
    DWORD dwInitialized;
    LPVOID lpSsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    LPVOID lpEntryInProgress;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STR FullDllName;
    UNICODE_STR BaseDllName;
    ULONG Flags;
    SHORT LoadCount;
    SHORT TlsIndex;
    LIST_ENTRY HashTableEntry;
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_FREE_BLOCK
{
    struct _PEB_FREE_BLOCK* pNext;
    DWORD dwSize;
} PEB_FREE_BLOCK, * PPEB_FREE_BLOCK;

typedef struct __PEB
{
    BYTE bInheritedAddressSpace;
    BYTE bReadImageFileExecOptions;
    BYTE bBeingDebugged;
    BYTE bSpareBool;
    LPVOID lpMutant;
    LPVOID lpImageBaseAddress;
    PPEB_LDR_DATA pLdr;
    LPVOID lpProcessParameters;
    LPVOID lpSubSystemData;
    LPVOID lpProcessHeap;
    PRTL_CRITICAL_SECTION pFastPebLock;
    LPVOID lpFastPebLockRoutine;
    LPVOID lpFastPebUnlockRoutine;
    DWORD dwEnvironmentUpdateCount;
    LPVOID lpKernelCallbackTable;
    DWORD dwSystemReserved;
    DWORD dwAtlThunkSListPtr32;
    PPEB_FREE_BLOCK pFreeList;
    DWORD dwTlsExpansionCounter;
    LPVOID lpTlsBitmap;
    DWORD dwTlsBitmapBits[2];
    LPVOID lpReadOnlySharedMemoryBase;
    LPVOID lpReadOnlySharedMemoryHeap;
    LPVOID lpReadOnlyStaticServerData;
    LPVOID lpAnsiCodePageData;
    LPVOID lpOemCodePageData;
    LPVOID lpUnicodeCaseTableData;
    DWORD dwNumberOfProcessors;
    DWORD dwNtGlobalFlag;
    LARGE_INTEGER liCriticalSectionTimeout;
    DWORD dwHeapSegmentReserve;
    DWORD dwHeapSegmentCommit;
    DWORD dwHeapDeCommitTotalFreeThreshold;
    DWORD dwHeapDeCommitFreeBlockThreshold;
    DWORD dwNumberOfHeaps;
    DWORD dwMaximumNumberOfHeaps;
    LPVOID lpProcessHeaps;
    LPVOID lpGdiSharedHandleTable;
    LPVOID lpProcessStarterHelper;
    DWORD dwGdiDCAttributeList;
    LPVOID lpLoaderLock;
    DWORD dwOSMajorVersion;
    DWORD dwOSMinorVersion;
    WORD wOSBuildNumber;
    WORD wOSCSDVersion;
    DWORD dwOSPlatformId;
    DWORD dwImageSubsystem;
    DWORD dwImageSubsystemMajorVersion;
    DWORD dwImageSubsystemMinorVersion;
    DWORD dwImageProcessAffinityMask;
    DWORD dwGdiHandleBuffer[34];
    LPVOID lpPostProcessInitRoutine;
    LPVOID lpTlsExpansionBitmap;
    DWORD dwTlsExpansionBitmapBits[32];
    DWORD dwSessionId;
    ULARGE_INTEGER liAppCompatFlags;
    ULARGE_INTEGER liAppCompatFlagsUser;
    LPVOID lppShimData;
    LPVOID lpAppCompatInfo;
    UNICODE_STR usCSDVersion;
    LPVOID lpActivationContextData;
    LPVOID lpProcessAssemblyStorageMap;
    LPVOID lpSystemDefaultActivationContextData;
    LPVOID lpSystemAssemblyStorageMap;
    DWORD dwMinimumStackCommit;
} _PEB, * _PPEB;

