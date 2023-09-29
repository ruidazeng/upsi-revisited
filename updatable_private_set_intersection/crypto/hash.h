// #ifndef UPSI_HASH_H
// #define UPSI_HASH_H

// #include "updatable_private_set_intersection/crypto/context.h"
// #include "absl/strings/string_view.h"

// #include <cstdlib>
// #include <cassert>
// #include <cstring>


// #define MAX_SIZE_BITS 10
// #define AES128_Rounds 10

// long long random_bytes(long long seed, uint8_t *dst, int size)
// {
//     srand(seed);
//     for(int i = 0; i < size; ++i)
//         dst[i] = rand();
//     return rand();
// }

// class hash_func
// {
// public:
//     long long _seed;
//     unsigned char data[256];
//     unsigned char hash_res[SHA256_DIGEST_LENGTH];
//     SHA256_CTX ctx;
//     hash_func(long long seed)
//     {
//         _seed = seed;
//     }
//     int hash(const unsigned char *msg, int msg_size)
//     {

//         assert(msg_size + 8 < 256);
//         SHA256_Init(&ctx);
//         memcpy(data, msg, sizeof(char) * msg_size);
//         for(int i = 0; i < 8; ++i)
//             data[msg_size + i] = (_seed >> (8 * i)) & (255);
//         SHA256_Update(&ctx, data, msg_size + 8);
//         SHA256_Final(hash_res, &ctx);
//         int res = 0;
//         for(int i = 0; i < 4; ++i)
//             res |= hash_res[i] << (i * 8);
//         return res;
//     }
// };

// hash_func h[3] = {hash_func(19260817), hash_func(20210221), hash_func(20200101)};

// void cuckoo_hash(const unsigned char *msg, int msg_size, int &res0, int &res1, int &res2, int array_len) //return 3 hash values
// {
//     res0 = h[0].hash(msg, msg_size) % array_len;
//     res1 = h[1].hash(msg, msg_size) % array_len;
//     res2 = h[2].hash(msg, msg_size) % array_len;
//     res0 = (res0 + array_len) % array_len;
//     res1 = (res1 + array_len) % array_len;
//     res2 = (res2 + array_len) % array_len;
// }

// #endif //UPSI_HASH_H