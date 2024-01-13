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
    std::string bytes = x.ToBytes(); // 32 bytes for SHA256 => obtain random_path as a byte string
    return bytes2uint64(bytes);
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
