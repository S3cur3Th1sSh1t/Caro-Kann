#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <windows.h>
#include <string.h>

int main() {
    const char* input_file_path = "decryptprotect.exe";

    HANDLE hFile = CreateFileA(input_file_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Failed to open input file.\n");
        return 1;
    }

    HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (hMapping == NULL) {
        printf("Failed to create file mapping.\n");
        CloseHandle(hFile);
        return 1;
    }

    LPVOID baseAddress = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (baseAddress == NULL) {
        printf("Failed to map view of file.\n");
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return 1;
    }

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)baseAddress;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((uint8_t*)baseAddress + dosHeader->e_lfanew);

    PIMAGE_SECTION_HEADER textSectionHeader = NULL;

    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        printf("Invalid PE file.\n");
        UnmapViewOfFile(baseAddress);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return 1;
    }

    PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)(ntHeaders + 1);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)sectionHeader[i].Name, ".text") == 0) {
            textSectionHeader = &sectionHeader[i];
            break;
        }
    }

    if (textSectionHeader == NULL) {
        printf(".text section not found.\n");
        UnmapViewOfFile(baseAddress);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return 1;
    }

    uint8_t* textSection = (uint8_t*)baseAddress + textSectionHeader->PointerToRawData;
    uint32_t textSectionSize = textSectionHeader->SizeOfRawData;

    printf("Size of .text section: %u bytes\n", textSectionSize);

    const char* output_file_path = "decryptprotect.bin";

    HANDLE hOutputFile = CreateFileA(output_file_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hOutputFile == INVALID_HANDLE_VALUE) {
        printf("Failed to create output file.\n");
        UnmapViewOfFile(baseAddress);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return 1;
    }

    DWORD bytesWritten;
    if (WriteFile(hOutputFile, textSection, textSectionSize, &bytesWritten, NULL) == 0 || bytesWritten != textSectionSize) {
        printf("Failed to write output file.\n");
        CloseHandle(hOutputFile);
        UnmapViewOfFile(baseAddress);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return 1;
    }

    CloseHandle(hOutputFile);
    UnmapViewOfFile(baseAddress);
    CloseHandle(hMapping);
    CloseHandle(hFile);

    printf("Extraction completed successfully.\n");
    return 0;
}
