#pragma once

#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>
#include "Helpers.cuh"


class AES {
private:
    static void SubWord(unsigned char* a);
    static void RotWord(unsigned char* a);
    static void XorWords(unsigned char* a, unsigned char* b, unsigned char* c);
    static void Rcon(unsigned char* a, int n);
    static void KeyExpansion(const unsigned char key[], unsigned char w[]);
public:
    static unsigned char* Encrypt(const unsigned char in[], unsigned int inLen, const unsigned char key[]);
    static unsigned char* Decrypt(const unsigned char in[], unsigned int inLen, const unsigned char key[]);
    static std::vector<unsigned char> Encrypt(std::vector<unsigned char> in, std::vector<unsigned char> key);
    static std::vector<unsigned char> Decrypt(std::vector<unsigned char> in, std::vector<unsigned char> key);
};