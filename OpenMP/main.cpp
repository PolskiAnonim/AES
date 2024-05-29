#include "AES.h"
#include <vector>
#include <iostream>
#include <chrono>
#include <string>
#include <fstream>

#include "Helpers.h"

//key //file
int main(int argc, char** argv) {

	std::vector<unsigned char> key = read_file(argv[1]);

	std::vector<unsigned char> plain = read_file(argv[2]);

	std::cout << "size: " << plain.size() << " B" << std::endl;


	auto start_time = std::chrono::high_resolution_clock::now();
	std::vector<unsigned char> c = AES::Encrypt(plain, key);
	auto end_time = std::chrono::high_resolution_clock::now();
	float enc_time = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time).count() / 1000.f;
	printf("encryption time %.3f ms\n", enc_time);

	start_time = std::chrono::high_resolution_clock::now();
	std::vector<unsigned char> dec = AES::Decrypt(c, key);
	end_time = std::chrono::high_resolution_clock::now();
	float dec_time = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time).count() / 1000.f;
	printf("decryption time %.3f ms\n", dec_time);
	check_byte_arrays(plain, dec);

	//write_file(enc_time, dec_time);
	try {
		if (argv[3][0] == '1' || argv[3][0] == '3') {
			write_file(c, "coded.txt");
		}
		if (argv[3][0] == '2' || argv[3][0] == '3') {
			write_file(dec, "decoded.txt");
		}
	}
	catch (std::exception e) {

	}
}


