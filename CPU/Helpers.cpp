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

const void write_file(float enc_time, float dec_time) {
	std::ofstream out("wyniki.txt", std::ios::app);
	out << enc_time << " " << dec_time << std::endl;
}

const void write_file(vector<unsigned char> text, string filename) {
	std::ofstream out(filename);
	for (auto& c : text) {
		out << c;
	}
}