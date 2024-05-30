#include "Helpers.h"

using std::vector;
using std::ifstream;
using std::string;

const vector<unsigned char> read_file(string file_path)
{
	vector<unsigned char> data;
	char act_byte;
	unsigned int counter = 0;
	ifstream infile;

	infile.open(file_path);

	while (!infile.eof())
	{
		infile.get(act_byte);
		data.push_back(act_byte);
	}

	infile.close();
	while (data.size() % 16 != 0) {
		data.push_back(0x00);
	}
	return data;
}

const std::vector<unsigned char> read_hex_file(std::string file_path)
{
	vector<unsigned char> data;
	ifstream infile;

	infile.open(file_path);

	unsigned int byte;
	std::string hex_byte;

	while (!infile.eof())
	{
		infile >> hex_byte;
		std::stringstream ss;
		ss << hex_byte;
		ss >> std::hex >> byte;
		data.push_back(static_cast<unsigned char>(byte));
	}

	infile.close();

	return data;
}


bool check_byte_arrays(const std::vector<unsigned char>& arr1, const std::vector<unsigned char>& arr2)
{
	if (arr1.size() != arr2.size())
		return false;

	for (size_t i = 0; i != arr1.size(); ++i)
	{
		if (arr1[i] != arr2[i])
		{
			std::cout << std::endl << "Error at index i2 = " << i << " " << arr1[i] << " " << (int)arr2[i] << std::endl;
			return false;
		}
	}

	return true;
}

const void write_file(vector<unsigned char> text, string filename) {
	std::ofstream out(filename);
	for (auto& c : text) {
		out << c;
	}
}

const void write_hex_file(vector<unsigned char> text, string filename) {
	std::ofstream out(filename);
	for (int i = 0; i < text.size(); i++) {
		const unsigned char c = text[i];
		out << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c) << " ";
	}
}