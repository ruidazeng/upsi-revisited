#pragma once

#include "upsi/crypto/big_num.h"
#include "upsi/crypto/context.h"
#include "emp-sh2pc/emp-sh2pc.h"

namespace upsi {


#define GC_SIZE 148

uint64_t bytes2uint64(const std::string& str);
uint64_t generateRandom64bits();
uint64_t BigNum2uint64(const BigNum &x); // mod 2^64
void bytes2bool(const std::string& str, bool* bool_val, int cnt = GC_SIZE);
void BigNum2bool(const BigNum &x, bool* bool_val, int cnt = GC_SIZE);
void BigNum2block(BigNum x, emp::block* bl, int cnt_block);
BigNum block2BigNum(emp::block* bl, int cnt_block, Context* ctx);
void PadBytes(std::string& str, int len);
}
