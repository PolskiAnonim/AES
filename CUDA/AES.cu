#include "AES.cuh"

extern int THREADS_PER_BLOCK;

void AES::RotWord(unsigned char* a) {
    unsigned char c = a[0];
    a[0] = a[1];
    a[1] = a[2];
    a[2] = a[3];
    a[3] = c;
}

void AES::SubWord(unsigned char* a) {
    for (int i = 0; i < 4; i++) {
        a[i] = sbox[a[i] / 16][a[i] % 16];
    }
}

void AES::Rcon(unsigned char* a, int n) {
    unsigned char c = 1;
    for (int i = 0; i < n - 1; i++) {
        c = (c << 1) ^ (((c >> 7) & 1) * 0x1b);
    }

    a[0] = c;
    a[1] = a[2] = a[3] = 0;
}

void AES::XorWords(unsigned char* a, unsigned char* b, unsigned char* c) {
    for (int i = 0; i < 4; i++) {
        c[i] = a[i] ^ b[i];
    }
}

void AES::KeyExpansion(const unsigned char key[], unsigned char w[]) {
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

        if (i / 4 % 8 == 0) {
            RotWord(temp);
            SubWord(temp);
            Rcon(rcon, i / (8 * 4));
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

__device__ void SubBytes(unsigned char state[4][4]) {
    int i, j;
    unsigned char t;
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            t = state[i][j];
            state[i][j] = sbox[t / 16][t % 16];
        }
    }
}

__device__ void ShiftRow(unsigned char state[4][4], int i, int n) {
    unsigned char tmp[4];
    int j = 0;
    for (; j < 4; j++) {
        tmp[j] = state[i][(j + n) % 4];
    }
    for (j = 0; j < 4; j++) {
        state[i][j] = tmp[j];
    }
}

__device__ void ShiftRows(unsigned char state[4][4]) {
    ShiftRow(state, 1, 1);
    ShiftRow(state, 2, 2);
    ShiftRow(state, 3, 3);
}

__device__ void MixColumns(unsigned char state[4][4]) {
    unsigned char temp_state[4][4] = {0};
    int i, j, k;
    for (i = 0; i < 4; ++i) {
        for (j = 0; j < 4; ++j) {
            for (k = 0; k < 4; ++k) {
                if (CMDS[i][j] == 1)
                    temp_state[i][k] ^= state[j][k];
                else
                    temp_state[i][k] ^= GF_MUL_TABLE[CMDS[i][j]][state[j][k]];
            }
        }
    }

    for (i = 0; i < 4; ++i) {
        for (j = 0; j < 4; ++j) {
            state[i][j] = temp_state[i][j];
        }
    }
}

__device__ void AddRoundKey(unsigned char state[4][4], unsigned char* key) {
    int i, j;
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            state[i][j] ^= key[i + 4 * j];
        }
    }
}

__device__ void SubWord(unsigned char* a) {
    for (int i = 0; i < 4; i++) {
        a[i] = sbox[a[i] / 16][a[i] % 16];
    }
}

__device__ void RotWord(unsigned char* a) {
    unsigned char c = a[0];
    a[0] = a[1];
    a[1] = a[2];
    a[2] = a[3];
    a[3] = c;
}

__device__ void XorWords(unsigned char* a, unsigned char* b, unsigned char* c) {
    for (int i = 0; i < 4; i++) {
        c[i] = a[i] ^ b[i];
    }
}

__device__ void InvSubBytes(unsigned char state[4][4]) {
    int i, j;
    unsigned char t;
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            t = state[i][j];
            state[i][j] = inv_sbox[t / 16][t % 16];
        }
    }
}

__device__ void InvMixColumns(unsigned char state[4][4]) {
    unsigned char temp_state[4][4] = { 0 };
    int i, j,k;
    for (i = 0; i < 4; ++i) {
        for (j = 0; j < 4; ++j) {
            for (k = 0; k < 4; ++k) {
                temp_state[i][k] ^= GF_MUL_TABLE[INV_CMDS[i][j]][state[j][k]];
            }
        }
    }

    for (i = 0; i < 4; ++i) {
        for (j = 0; j < 4; ++j) {
            state[i][j] = temp_state[i][j];
        }
    }
}

__device__ void InvShiftRows(unsigned char state[4][4]) {
    ShiftRow(state, 1, 4 - 1);
    ShiftRow(state, 2, 4 - 2);
    ShiftRow(state, 3, 4 - 3);
}

__device__ void XorBlocks(const unsigned char* a, const unsigned char* b,
    unsigned char* c, uint8_t len) {
    for (unsigned int i = 0; i < len; i++) {
        c[i] = a[i] ^ b[i];
    }
}

__global__ void EncryptBlock(const unsigned char in[], unsigned char out[],
    unsigned char* roundKeys, unsigned int len) {

    unsigned int offset = (blockIdx.x * blockDim.x + threadIdx.x)*16;
    if (offset >= len) return;
    unsigned char state[4][4];
    int i,j,round;

    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            state[i][j] = in[offset+i + 4 * j];
        }
    }

    AddRoundKey(state, roundKeys);

    for (round = 1; round <= 14-1; round++) {
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
            out[offset+i + 4 * j] = state[i][j];
        }
    }
}

__global__ void DecryptBlock(const unsigned char in[], unsigned char out[],
    unsigned char* roundKeys, unsigned int len) {
    
    unsigned int offset = (blockIdx.x * blockDim.x + threadIdx.x) * 16;
    if (offset >= len) return;
    unsigned char state[4][4];
    int i, j, round;

    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            state[i][j] = in[offset + i + 4 * j];
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
            out[offset+i + 4 * j] = state[i][j];
        }
    }
}

unsigned char* AES::Encrypt(const unsigned char in[], unsigned int len, const unsigned char key[]) {
    unsigned char* out = new unsigned char[len];
    unsigned char* roundKeys = new unsigned char[4 * 4 * (14 + 1)];
    KeyExpansion(key, roundKeys);

    unsigned int numBlocks = (len + (THREADS_PER_BLOCK * 16 - 1)) / (THREADS_PER_BLOCK * 16);
    unsigned char* d_in;
    unsigned char* d_out;
    unsigned char* d_roundKeys;

    cudaMalloc(&d_in, len);
    cudaMalloc(&d_out, len);
    cudaMalloc(&d_roundKeys, 4 * 4 * (14 + 1));

    cudaMemcpyAsync(d_in, in, len, cudaMemcpyHostToDevice);
    cudaMemcpyAsync(d_roundKeys, roundKeys, 4 * 4 * (14 + 1), cudaMemcpyHostToDevice);

    EncryptBlock<<<numBlocks, THREADS_PER_BLOCK >>> (d_in, d_out, d_roundKeys,len);

    cudaMemcpyAsync(out, d_out, len, cudaMemcpyDeviceToHost);

    cudaFree(d_in);
    cudaFree(d_out);
    cudaFree(d_roundKeys);
    delete[] roundKeys;

    return out;
}

unsigned char* AES::Decrypt(const unsigned char in[], unsigned int len, const unsigned char key[]) {
    unsigned char* out = new unsigned char[len];
    unsigned char* roundKeys = new unsigned char[4 * 4 * (14 + 1)];
    AES::KeyExpansion(key, roundKeys);

    unsigned int numBlocks = (len + (THREADS_PER_BLOCK * 16 - 1)) / (THREADS_PER_BLOCK * 16);
    unsigned char* d_in;
    unsigned char* d_out;
    unsigned char* d_roundKeys;

    cudaMalloc(&d_in, len);
    cudaMalloc(&d_out, len);
    cudaMalloc(&d_roundKeys, 4 * 4 * (14 + 1));

    cudaMemcpyAsync(d_in, in, len, cudaMemcpyHostToDevice);
    cudaMemcpyAsync(d_roundKeys, roundKeys, 4 * 4 * (14 + 1), cudaMemcpyHostToDevice);

    DecryptBlock <<<numBlocks, THREADS_PER_BLOCK >>> (d_in, d_out, d_roundKeys, len);

    cudaMemcpyAsync(out, d_out, len, cudaMemcpyDeviceToHost);

    cudaFree(d_in);
    cudaFree(d_out);
    cudaFree(d_roundKeys);
    delete[] roundKeys;

    return out;
}

std::vector<unsigned char> AES::Encrypt(std::vector<unsigned char> in, std::vector<unsigned char> key) {
    unsigned char* out = Encrypt(in.data(), (unsigned int)in.size(), key.data());
    std::vector<unsigned char> v(out, out + in.size());
    delete[] out;
    return v;
}

std::vector<unsigned char> AES::Decrypt(std::vector<unsigned char> in, std::vector<unsigned char> key) {
    unsigned char* out = Decrypt(in.data(), (unsigned int)in.size(), key.data());
    std::vector<unsigned char> v(out, out + in.size());
    delete[] out;
    return v;
}