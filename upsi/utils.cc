#include "utils.h"

#include <chrono>
#include <iomanip>

#include "upsi/util/elgamal_proto_util.h"


namespace upsi {


bool AbslParseFlag(absl::string_view text, Functionality* func, std::string* err) {
    if (text == "PSI") { *func = Functionality::PSI; }
    else if (text == "CA") { *func = Functionality::CA; }
    else if (text == "SUM") { *func = Functionality::SUM; }
    else if (text == "SS") { *func = Functionality::SS; }
    else { 
        *err = "unknown functionality"; 
        return false;
    }
    return true;
}

std::string AbslUnparseFlag(Functionality func) {
    switch (func) {
        case Functionality::PSI:
            return "PSI";
        case Functionality::CA:
            return "CA";
        case Functionality::SUM:
            return "SUM";
        case Functionality::SS:
            return "SS";
        default:
            return "CA";
    }
}

StatusOr<std::vector<CiphertextAndPayload>> DeserializeCiphertextAndPayloads(
    const google::protobuf::RepeatedPtrField<EncryptedElement> serialized,
    Context* ctx,
    ECGroup* group
) {
    std::vector<CiphertextAndPayload> ciphertexts;
    for (const EncryptedElement& element : serialized) {
        
        ciphertexts.push_back(
            std::make_pair(
                ctx->CreateBigNum(element.element()),
                ctx->CreateBigNum(element.payload())
            )
        );
    }
    return ciphertexts;
}

StatusOr<std::vector<Element>> DeserializeElement(
    const EncryptedSet serialized,
    Context* ctx,
    ECGroup* group
) {
    std::vector<Element> ciphertexts;
    for (const std::string& element : serialized.elements()) {
        ciphertexts.push_back(ctx->CreateBigNum(element));
    }
    return ciphertexts;
}

//convert byte hash to binary hash
std::string Byte2Binary(const std::string &byte_hash) {
    std::string binary_hash = "";
    for (char const &c: byte_hash) {
        binary_hash += std::bitset<8>(c).to_string();
    }
    return binary_hash;
}

void PadBytes(std::string& str, int len) {
	int cnt_zero = len - str.length();
	if(cnt_zero > 0) str = std::string(cnt_zero, 0) + str;
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

////////////////////////////////////////////////////////////////////////////////
// COMPUTE BINARY HASH
////////////////////////////////////////////////////////////////////////////////
template<typename T>
BinaryHash computeBinaryHash(T &elem) {
	return elem;
}

template<>
BinaryHash computeBinaryHash(Element &elem) {
	Context ctx;
    return Byte2Binary(
        ctx.Sha256String(elem.ToBytes())
    );
}

template<>
BinaryHash computeBinaryHash(ElementAndPayload &elem) {
    return computeBinaryHash(std::get<0>(elem));
}


////////////////////////////////////////////////////////////////////////////////
// ELEMENT COPY
////////////////////////////////////////////////////////////////////////////////


template<>
ElementAndPayload elementCopy(const ElementAndPayload& elem) {
    return elem;
}

////////////////////////////////////////////////////////////////////////////////

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

// generate random binary hash
BinaryHash generateRandomHash() {
	//TODO: should be replaced by PRF
	Context ctx;
	std::string random_bytes = ctx.GenerateRandomBytes(32); // 32 bytes for SHA256 => obtain random_path as a byte string
	return random_bytes;
}

// generate random binary hash for cnt paths
void generateRandomHash(int cnt, std::vector<std::string> &hsh) {
	for (int i = 0; i < cnt; ++i) {
		hsh.push_back(generateRandomHash());
	}
}

StatusOr<elgamal::Ciphertext> elgamalEncrypt(const ECGroup* ec_group, std::unique_ptr<elgamal::PublicKey> public_key, const BigNum& elem) {
	//std::unique_ptr<elgamal::PublicKey> key_ptr = std::move(absl::WrapUnique(&public_key));
  	ASSIGN_OR_RETURN(ECPoint g, public_key->g.Clone());
	ElGamalEncrypter encrypter = ElGamalEncrypter(ec_group, std::move(public_key));

    ASSIGN_OR_RETURN(ECPoint g_to_m, std::move(g.Mul(elem))); //g^m
    ASSIGN_OR_RETURN(elgamal::Ciphertext now, std::move(encrypter.Encrypt(g_to_m)));
    return std::move(now);
}

std::string GetRandomNumericString(size_t length, bool padding) {
	std::string output;
    if (padding) {
		absl::StrAppend(&output, "1");
    } else {
		absl::StrAppend(&output, "0");
    }
	for (size_t i = 1; i < length; i++) {
		std::string next_char(1, rand() % 10 + '0');
		absl::StrAppend(&output, next_char);
	}
	return output;
}

std::string GetRandomSetElement() {
    return GetRandomNumericString(ELEMENT_STR_LENGTH, false);
}

Element GetRandomPadElement(Context* ctx) {
    return ctx->CreateBigNum(std::stoull(
        GetRandomNumericString(ELEMENT_STR_LENGTH, true)
    ));
}

Timer::Timer(std::string msg, std::string color) : message(msg), color(color) {
    start = std::chrono::high_resolution_clock::now();
}

void Timer::lap() {
    start = std::chrono::high_resolution_clock::now();
    using_laps = true;
}

void Timer::stop() {
    auto stop = std::chrono::high_resolution_clock::now();
    std::chrono::duration<float> elapsed = stop - start;
    if (using_laps) {
        laps.push_back(elapsed);
    } else {
        std::cout << std::fixed << std::setprecision(3);
        std::cout << color << message << " (s)\t: ";
        std::cout << elapsed.count() << RESET << std::endl;
    }
}

void Timer::print() {
    float average = 0;
    float min = std::numeric_limits<float>::max();
    float max = 0;
    for (const auto& lap : laps) {
        average += lap.count();
        if (lap.count() < min) { min = lap.count(); }
        else if (lap.count() > max) { max = lap.count(); }
    }
    average /= laps.size();

    std::cout << std::fixed << std::setprecision(3);
    std::cout << color << message << " (s)\t: ";
    std::cout << average << " (AVG), ";
    std::cout << min << " (MIN), ";
    std::cout << max << " (MAX)" << RESET << std::endl;
}

}
