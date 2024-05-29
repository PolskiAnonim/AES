#include "AES.h"

extern int NUM_THREADS;

void AES::KeyExpansion(const unsigned char key[], unsigned char w[])
{
    unsigned char temp[4];
    unsigned char rcon[4];

    int i = 0;
    while (i < 4 * 8) {
        w[i] = key[i];
        i++;
    }

    while (i < 16 * (14 + 1)) {
        temp[0] = w[i - 4 + 0];
        temp[1] = w[i - 4 + 1];
        temp[2] = w[i - 4 + 2];
        temp[3] = w[i - 4 + 3];

        if (i / 4 % 14 == 0) {
            RotWord(temp);
            SubWord(temp);
            Rcon(rcon, i / (14 * 4));
            XorWords(temp, rcon, temp);
        }
        else if (i / 4 % 8 == 4) {
            SubWord(temp);
        }

        w[i + 0] = w[i - 4 * 8] ^ temp[0];
        w[i + 1] = w[i + 1 - 4 * 8] ^ temp[1];
        w[i + 2] = w[i + 2 - 4 * 8] ^ temp[2];
        w[i + 3] = w[i + 3 - 4 * 8] ^ temp[3];
        i += 4;
    }
}

void AES::SubBytes(unsigned char state[4][4]) {
    int i, j;
    unsigned char t;
    for (i = 0; i < 4; i++) 
    {
        for (j = 0; j < 4; j++)
        {
            t = state[i][j];
            state[i][j] = sbox[t / 16][t % 16];
        }
    }
}

void AES::ShiftRow(unsigned char state[4][4], int i, int n)
{  // shift row i on n positions
    unsigned char tmp[4];
    for (int j = 0; j < 4; j++) 
    {
        tmp[j] = state[i][(j + n) % 4];
    }
    memcpy(state[i], tmp, 4);
}

void AES::ShiftRows(unsigned char state[4][4])
{
    ShiftRow(state, 1, 1);
    ShiftRow(state, 2, 2);
    ShiftRow(state, 3, 3);
}

void AES::MixColumns(unsigned char state[4][4])
{
    int i, j, k;
    unsigned char temp_state[4][4];
    memset(temp_state, 0, 16);
    for (i = 0; i < 4; ++i)
    {
        for (k = 0; k < 4; ++k)
        {
            for (j = 0; j < 4; ++j)
            {
                if (CMDS[i][k] == 1)
                    temp_state[i][j] ^= state[k][j];
                else
                    temp_state[i][j] ^= GF_MUL_TABLE[CMDS[i][k]][state[k][j]];
            }
        }
    }

    memcpy(state, temp_state, 16);

}

void AES::AddRoundKey(unsigned char state[4][4], unsigned char* key) 
{
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            state[i][j] = state[i][j] ^ key[4*i+j];
        }
    }
}

void AES::SubWord(unsigned char* a)
{
    for (int i = 0; i < 4; i++)
    {
        a[i] = sbox[a[i] / 16][a[i] % 16];
    }
}

void AES::RotWord(unsigned char* a)
{
    unsigned char c = a[0];
    a[0] = a[1];
    a[1] = a[2];
    a[2] = a[3];
    a[3] = c;
}

void AES::XorWords(unsigned char* a, unsigned char* b, unsigned char* c) {
    for (int i = 0; i < 4; i++) {
        c[i] = a[i] ^ b[i];
    }
}

void AES::Rcon(unsigned char* a, int n)
{
    unsigned char c = 1;
    for (int i = 0; i < n - 1; i++)
    {
        c = (c << 1) ^ (((c >> 7) & 1) * 0x1b);
    }

    a[0] = c;
    a[1] = a[2] = a[3] = 0;
}

void AES::InvSubBytes(unsigned char state[4][4])
{
    int i, j;
    unsigned char t;
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 4; j++)
        {
            t = state[i][j];
            state[i][j] = inv_sbox[t / 16][t % 16];
        }
    }
}

void AES::InvMixColumns(unsigned char state[4][4]) {
    unsigned char temp_state[4][4];

    memset(temp_state, 0, 16);
 
    for (int i = 0; i < 4; ++i)
    {
        for (int k = 0; k < 4; ++k)
        {
            for (int j = 0; j < 4; ++j)
            {
                temp_state[i][j] ^= GF_MUL_TABLE[INV_CMDS[i][k]][state[k][j]];
            }
        }
    }

    memcpy(state, temp_state, 16);
}

void AES::InvShiftRows(unsigned char state[4][4]) {
    ShiftRow(state, 1, 4 - 1);
    ShiftRow(state, 2, 4 - 2);
    ShiftRow(state, 3, 4 - 3);
}

void AES::XorBlocks(const unsigned char* a, const unsigned char* b,
    unsigned char* c, unsigned int len) {
    for (unsigned int i = 0; i < len; i++) {
        c[i] = a[i] ^ b[i];
    }
}

void AES::EncryptBlock(const unsigned char in[], unsigned char out[],
    unsigned char* roundKeys) {
    unsigned char state[4][4];
    int i, j, round;

    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            state[i][j] = in[4*i+j];
        }
    }

    AddRoundKey(state, roundKeys);

    for (round = 1; round <= 14 - 1; round++) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, roundKeys + round * 4 * 4);
    }

    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, roundKeys + 14 * 4 * 4);

    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            out[4*i+j] = state[i][j];
        }
    }
}

void AES::DecryptBlock(const unsigned char in[], unsigned char out[],
    unsigned char* roundKeys) {
    unsigned char state[4][4];
    int i, j, round;

    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            state[i][j] = in[4*i+j];
        }
    }

    AddRoundKey(state, roundKeys + 14 * 4 * 4);

    for (round = 14 - 1; round >= 1; round--) {
        InvSubBytes(state);
        InvShiftRows(state);
        AddRoundKey(state, roundKeys + round * 4 * 4);
        InvMixColumns(state);
    }

    InvSubBytes(state);
    InvShiftRows(state);
    AddRoundKey(state, roundKeys);

    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            out[4*i+j] = state[i][j];
        }
    }
}

unsigned char* AES::Encrypt(const unsigned char in[], unsigned int len,
    const unsigned char key[]) {
    unsigned char* out = new unsigned char[len];
    unsigned char* roundKeys = new unsigned char[4 * 4 * (14 + 1)];
    KeyExpansion(key, roundKeys);

    #pragma omp parallel for num_threads(NUM_THREADS)
    for (int i = 0; i < len; i += 16) {
        EncryptBlock(in + i, out + i, roundKeys);
    }

    delete[] roundKeys;

    return out;
}

unsigned char* AES::Decrypt(const unsigned char in[], unsigned int len,
    const unsigned char key[]) {
    unsigned char* out = new unsigned char[len];
    unsigned char* roundKeys = new unsigned char[16 * (14 + 1)];
    KeyExpansion(key, roundKeys);
    #pragma omp parallel for num_threads(NUM_THREADS)
    for (int i = 0; i < len; i += 16) {
        DecryptBlock(in + i, out + i, roundKeys);
    }

    delete[] roundKeys;

    return out;
}

std::vector<unsigned char> AES::Encrypt(std::vector<unsigned char> in,
    std::vector<unsigned char> key) {
    unsigned char* out = Encrypt(in.data(), (unsigned int)in.size(),
        key.data());
    std::vector<unsigned char> v(out, out + in.size());
    delete[] out;
    return v;
}

std::vector<unsigned char> AES::Decrypt(std::vector<unsigned char> in,
    std::vector<unsigned char> key) {
    unsigned char* out = Decrypt(in.data(), (unsigned int)in.size(),
        key.data());
    std::vector<unsigned char> v(out, out + in.size());
    delete[] out;
    return v;
}