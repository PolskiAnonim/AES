#include <iostream>
#include <chrono>
#include <string>
#include <fstream>

#include "Helpers.cuh"
#include "AES.cuh"

namespace main_functions {
    void encryption(std::vector<unsigned char>& key, std::string input_file_name, std::string output_option)
    {
        std::cout << "Reading file..." << std::endl;
        std::vector<unsigned char> data = read_file(input_file_name);
        std::cout << "Size: " << data.size() << " B" << std::endl;

        std::cout << "Encrypting data..." << std::endl;

        auto start_time = std::chrono::high_resolution_clock::now();
        std::vector<unsigned char> cipher = AES::Encrypt(data, key);
        auto end_time = std::chrono::high_resolution_clock::now();
        float enc_time = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time).count() / 1000.f;
        printf("Encryption time %.3f ms\n", enc_time);

        if (output_option != "") {
            std::cout << "Writing file..." << std::endl;
            write_hex_file(cipher, output_option);
        }
    }

    void decryption(std::vector<unsigned char>& key, std::string input_file_name, std::string output_option)
    {
        std::cout << "Reading file..." << std::endl;
        std::vector<unsigned char> data = read_hex_file(input_file_name);
        std::cout << "Size: " << data.size() << " B" << std::endl;

        std::cout << "Decrypting data..." << std::endl;

        auto start_time = std::chrono::high_resolution_clock::now();
        std::vector<unsigned char> plain = AES::Decrypt(data, key);
        auto end_time = std::chrono::high_resolution_clock::now();
        float dec_time = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time).count() / 1000.f;
        printf("Decryption time %.3f ms\n", dec_time);

        if (output_option != "") {
            std::cout << "Writing file..." << std::endl;
            write_file(plain, output_option);
        }
    }

    void both(std::vector<unsigned char>& key, std::string input_file_name) {
        std::cout << "Reading file..." << std::endl;
        std::vector<unsigned char> data = read_file(input_file_name);
        std::cout << "Size: " << data.size() << " B" << std::endl;

        std::cout << "Encrypting data..." << std::endl;

        auto start_time = std::chrono::high_resolution_clock::now();
        std::vector<unsigned char> cipher = AES::Encrypt(data, key);
        auto end_time = std::chrono::high_resolution_clock::now();
        float enc_time = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time).count() / 1000.f;
        printf("Encryption time %.3f ms\n", enc_time);

        std::cout << "Decrypting data..." << std::endl;
        start_time = std::chrono::high_resolution_clock::now();
        std::vector<unsigned char> plain = AES::Decrypt(cipher, key);
        end_time = std::chrono::high_resolution_clock::now();
        float dec_time = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time).count() / 1000.f;
        printf("Decryption time %.3f ms\n", dec_time);
        check_byte_arrays(data, plain);
    }
}

int main(int argc, char** argv) {
    // Ustawienie flag urządzenia - w zasadzie bardziej dla znormalizowania czasu pierwszego dostępu
    cudaError_t cudaStatus = cudaSetDeviceFlags(cudaDeviceScheduleBlockingSync);
    if (cudaStatus != cudaSuccess) {
        fprintf(stderr, "cudaSetDeviceFlags failed!");
        return 1;
    }


    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << "<operation> <key file> <input file> [<output option>]" << std::endl;
        std::cerr << "Where: <operation> - encrypt/decrypt/both, <output operation> - name of file to save or nothing" << std::endl;
        std::cerr << "(only for encrypt and decrypt)" << std::endl;
        return 1;
    }
    std::string operation = argv[1];
    std::vector<unsigned char> key = read_file(argv[2]);
    std::string input_file_name = argv[3];
    std::string output_option = (argc > 4) ? argv[4] : "";

    if (operation == "encrypt") {
        main_functions::encryption(key, input_file_name, output_option);
    }
    else if (operation == "decrypt") {
        main_functions::decryption(key, input_file_name, output_option);
    }
    else if (operation == "both") {
        main_functions::both(key, input_file_name);
    }
    else {
        std::cerr << "Invalid operation. Use 'encrypt' or 'decrypt' or 'both'." << std::endl;
        return 1;
    }

    return 0;
}
