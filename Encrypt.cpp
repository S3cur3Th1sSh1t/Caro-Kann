#include <iostream>
#include <fstream>
#include <vector>
#include <cstdint>
#include <stddef.h>
#include <stdint.h>
#include <Windows.h> 

// Paste your xor32 function here

void longKey()
{
    asm(".byte 0x01, 0x02, 0x03, 0x04");
}

void xor32(LPVOID buf, DWORD bufSize)
{
    uint8_t* buf8 = (uint8_t*)buf;
    // the xorKey is the cast value of our LongKey function, which can be used as a pointer to an char array
    uint32_t xorKey = *(uint32_t*)longKey;


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


int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " input_file output_file" << std::endl;
        return 1;
    }

    const char* inputFileName = argv[1];
    const char* outputFileName = argv[2];

    
    // Open the input file
    std::ifstream inputFile(inputFileName, std::ios::binary);
    if (!inputFile) {
        std::cerr << "Error: Could not open input file." << std::endl;
        return 1;
    }

    // Read the input file into a vector
    std::vector<uint8_t> inputData(
        (std::istreambuf_iterator<char>(inputFile)),
        (std::istreambuf_iterator<char>())
    );

    // Apply the XOR encryption
    xor32(inputData.data(), inputData.size());

    // Open the output file
    std::ofstream outputFile(outputFileName, std::ios::binary);
    if (!outputFile) {
        std::cerr << "Error: Could not open output file." << std::endl;
        return 1;
    }

    // Write the encrypted data to the output file
    outputFile.write(reinterpret_cast<const char*>(inputData.data()), inputData.size());

    std::cout << "Encryption complete." << std::endl;

    return 0;
}

