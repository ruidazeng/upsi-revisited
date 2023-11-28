#include "utils.h"

namespace updatable_private_set_intersection {



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
BinaryHash computeBinaryHash(T elem) {
	return elem;
}

template<>
BinaryHash computeBinaryHash(std::string elem) {
	Context ctx;
    absl::string_view sv_element = elem;
    std::string sha_string = ctx.Sha256String(sv_element);
    return Byte2Binary(sha_string);
}

// generate random binary hash
BinaryHash generateRandomHash() {
	//TODO: should be replaced by PRF
	// Both parties shared a key and call PRF 
	// Parties should call PRF in the same order to ensure they get the same random numbers each time
	// Then there is no need to send the random paths to the other party
	Context ctx;
	std::string random_bytes = ctx.GenerateRandomBytes(32); // 32 bytes for SHA256 => obtain random_path as a byte string
	return Byte2Binary(random_bytes);
}

// generate random binary hash for cnt paths
void generateRandomHash(int cnt, std::vector<BinaryHash> &hsh) {
	for (int i = 0; i < cnt; ++i) {
		hsh.push_back(generateRandomHash());
	}
}

StatusOr<elgamal::Ciphertext> ElGamal_encrypt(ElGamalEncrypter& encrypter, ECGroup* ec_group, BigNum& g, std::string elem) {
    absl::string_view str = elem;
	ASSIGN_OR_RETURN(ECPoint m, ec_group->CreateECPoint(str));
    ASSIGN_OR_RETURN(ECPoint g_to_m, g.Mul(m)); //g^m
    ASSIGN_OR_RETURN(elgamal::Ciphertext now, encrypter.Encrypt(g_to_m));
    return now;
}

}
