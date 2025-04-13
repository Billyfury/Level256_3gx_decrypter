#include <iostream>
#include <fstream>
#include <vector>


using uint = unsigned int;

void decrypt(uint* output, const uint* input, uint size) {

    uint i;

    // inverse bits
    for (i = 0; size >> 2 != i; i++) {
        output[i] = ~input[i];
    }

    // Key
    const uint TMP_DIFF_KEY    = 0x63DA901F;
    const uint XOR_KEY  = 0x4B0C9A12;
    const int DIFF_KEY  = 0x5AE007DF;

    // tmp
    uint *file_ptr  = output - 1;
    uint pre_key      = 0x63DA901F;
    uint tmp_key      = 0x63DA901F;

    // decryption
    for (uint j = 0; j < i; j++) {
        uint raw = *(++file_ptr);
        uint tmp = pre_key + TMP_DIFF_KEY;
        pre_key += (raw ^ XOR_KEY);
        *file_ptr = (tmp_key ^ raw) ^ (j * (tmp_key + DIFF_KEY));
        tmp_key = tmp ^ raw;
    }

}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cout << "Level256 Network 3GX Decrypter by Hidegon <3" << std::endl;
        std::cout << "Usage: " << argv[0] << " <encrypted file name (only the code section)> <output file name>" << std::endl;
        return 1;
    }

    std::ifstream encrypted_file(argv[1], std::ios::binary | std::ios::ate);
    if (!encrypted_file) {
        std::cerr << "Could not open the encrypted file: " << argv[1] << std::endl;
        return 1;
    }

    // Start address of the code section
    uint32_t code_offset = 0x240;

    // Get size of the code section
    uint32_t code_size;
    encrypted_file.seekg(0x5C, std::ios::beg);
    encrypted_file.read(reinterpret_cast<char*>(&code_size), sizeof(code_size));

    encrypted_file.seekg(code_offset, std::ios::beg);
    std::vector<uint> input(code_size / 4);
    std::vector<uint> output(code_size / 4);

    if (!encrypted_file.read(reinterpret_cast<char*>(input.data()), code_size)) {
        std::cerr << "Could not read the code section" << std::endl;
        return 1;
    }

    decrypt(output.data(), input.data(), static_cast<uint>(code_size));

    std::ofstream decrypted_file(argv[2], std::ios::binary);
    if (!decrypted_file) {
        std::cerr << "Could not open the decrypted file: " << argv[2] << std::endl;
        return 1;
    }

    if (!decrypted_file.write(reinterpret_cast<char*>(output.data()), code_size)) {
        std::cerr << "Failed to write the decrypted data." << std::endl;
        return 1;
    }

    std::cout << "Success!" << std::endl;
    return 0;
}
