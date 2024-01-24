#include "upsi/util/gc_util.h"

#include "upsi/crypto/context.h"
#include "emp-sh2pc/emp-sh2pc.h"

namespace upsi {

uint64_t bytes2uint64(const std::string& str) { //str: big-endian form
    uint64_t res = 0;
    int len = str.length();
    for (int i = std::max(0, len - 8); i < len; ++i) {
        res = (res << 8) + (uint8_t)str[i];
    }
    return res;
}

uint64_t generateRandom64bits() {
    Context ctx;
    std::string random_bytes = ctx.GenerateRandomBytes(8); // 32 bytes for SHA256 => obtain random_path as a byte string
    return bytes2uint64(random_bytes);
}

uint64_t BigNum2uint64(const BigNum &x) {
    std::string bytes = x.ToBytes();
    return bytes2uint64(bytes);
}

void bytes2bool(const std::string& str, bool* bool_val, int cnt) {
    int len = str.length(), cnt_byte = (cnt >> 3), p = 0, rem = cnt & 7;
    assert((len << 3) >= cnt);
    if(rem) {
    	uint8_t tmp = str[len - cnt_byte - 1];
    	for (int i = rem - 1; i >= 0; --i) bool_val[p++] = ((tmp >> i) & 1);
    }
    for (int i = len - cnt_byte; i < len; ++i) {
    	uint8_t tmp = str[i];
        for (int j = 7; j >= 0; --j) bool_val[p++] = ((tmp >> j) & 1);
    }
}

void BigNum2bool(const BigNum &x, bool* bool_val, int cnt) {
    Context ctx;
    BigNum max_value = ctx.One() << (cnt + 1);
    BigNum tmp = ctx.RandomOracleSha256(x.ToBytes(), max_value);
    return bytes2bool(tmp.ToBytes(), bool_val, cnt);
}

void BigNum2block(BigNum x, emp::block* bl, int cnt_block) {
	std::string str = x.ToBytes();
	PadBytes(str, cnt_block << 4);
	for (int i = 0; i < cnt_block; ++i) {
		const char* cur_ptr = &str[i << 4];
		bl[i] = _mm_loadu_si128(reinterpret_cast<const __m128i*>(cur_ptr));
	}
}

BigNum block2BigNum(emp::block* bl, int cnt_block, Context* ctx) {
	const char* bytes = reinterpret_cast<const char*>(bl);
	std::string str = std::string(bytes, cnt_block << 4);
	return ctx->CreateBigNum(str);
}

void PadBytes(std::string& str, int len) {
	int cnt_zero = len - str.length();
	if(cnt_zero > 0) str = std::string(cnt_zero, 0) + str;
}

}
