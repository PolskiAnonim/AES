#pragma once

#include <cstdio>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
#include "Helpers.h"

static class AES {
private:
    static void KeyExpansion(const unsigned char key[], unsigned char w[]);

    static void SubBytes(unsigned char state[4][4]);

    static void ShiftRow(unsigned char state[4][4], int i, int n);

    static void ShiftRows(unsigned char state[4][4]);

    static void MixColumns(unsigned char state[4][4]);

    static void AddRoundKey(unsigned char state[4][4], unsigned char* key);

    static void SubWord(unsigned char* a);

    static void RotWord(unsigned char* a);

    static void XorWords(unsigned char* a, unsigned char* b, unsigned char* c);

    static void Rcon(unsigned char* a, int n);

    static void InvSubBytes(unsigned char state[4][4]);

    static void InvMixColumns(unsigned char state[4][4]);

    static  void InvShiftRows(unsigned char state[4][4]);

    static void XorBlocks(const unsigned char* a, const unsigned char* b, unsigned char* c, unsigned int len);

    static void EncryptBlock(const unsigned char in[], unsigned char out[], unsigned char* roundKeys);

    static void DecryptBlock(const unsigned char in[], unsigned char out[], unsigned char* roundKeys);


public:
    static unsigned char* Encrypt(const unsigned char in[], unsigned int inLen, const unsigned char key[]);

    static unsigned char* Decrypt(const unsigned char in[], unsigned int inLen, const unsigned char key[]);

    static std::vector<unsigned char> Encrypt(std::vector<unsigned char> in,
        std::vector<unsigned char> key);

    static std::vector<unsigned char> Decrypt(std::vector<unsigned char> in,
        std::vector<unsigned char> key);
};