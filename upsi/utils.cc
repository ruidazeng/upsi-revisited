#include "utils.h"

#include <chrono>
#include <iomanip>

namespace upsi {

StatusOr<ECPoint> exponentiate(ECGroup* group, const BigNum& m) {
    ASSIGN_OR_RETURN(ECPoint generator, group->GetPointAtInfinity());
    return generator.Mul(m);
}

//convert byte hash to binary hash
std::string Byte2Binary(const std::string &byte_hash) {
    std::string binary_hash = "";
    for (char const &c: byte_hash) {
        binary_hash += std::bitset<8>(c).to_string();
    }
    return binary_hash;
}

// compute binary hash for an element
// TODO: other types for T
template<typename T>
BinaryHash computeBinaryHash(T &elem) {
	return elem;
}

template<>
BinaryHash computeBinaryHash(std::string &elem) {
	Context ctx;
    absl::string_view sv_element = elem;
    std::string sha_string = ctx.Sha256String(sv_element);
    return Byte2Binary(sha_string);
}

template<>
BinaryHash computeBinaryHash(elgamal::Ciphertext &elem) {
	assert(0);
	std::string rs;
    return rs;
}


template<>
elgamal::Ciphertext elementCopy(const elgamal::Ciphertext &elem) {
	elgamal::Ciphertext rs = elgamal::CloneCiphertext(elem).value();
	return rs;
}

template<>
std::string elementCopy(const std::string &elem) {
	std::string rs = elem;
	return rs;
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

int64_t NumericString2uint(const std::string &str) { //str should be fixed length
	int64_t x = 0;
	int len = str.length();
	for (int i = 0; i < len; ++i) {
		x = x * 10 + str[i] - '0';
	}
	return x;
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

std::string GetRandomPadElement() {
    return GetRandomNumericString(ELEMENT_STR_LENGTH, true);
}

Timer::Timer(std::string msg, std::string color) : message(msg), color(color) {
    start = std::chrono::high_resolution_clock::now();
}

void Timer::stop() {
    auto stop = std::chrono::high_resolution_clock::now();
    std::chrono::duration<float> elapsed = stop - start;
    std::cout << std::fixed << std::setprecision(3);
    std::cout << color << message << " (s)\t: ";
    std::cout << elapsed.count() << RESET << std::endl;
}

}
