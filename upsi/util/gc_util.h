#pragma once

#include "upsi/crypto/big_num.h"
#include "upsi/crypto/context.h"
#include "emp-sh2pc/emp-sh2pc.h"

namespace upsi {

uint64_t bytes2uint64(const std::string& str);
uint64_t generateRandom64bits();
uint64_t BigNum2uint64(const BigNum &x); // mod 2^64
void BigNum2block(BigNum x, emp::block* bl, int cnt_block);
BigNum block2BigNum(emp::block* bl, int cnt_block, Context* ctx);
void PadBytes(std::string& str, int len);
}
