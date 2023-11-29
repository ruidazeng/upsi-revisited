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

StatusOr<elgamal::Ciphertext> elgamalEncrypt(const ECGroup* ec_group, std::unique_ptr<elgamal::PublicKey> public_key, const BigNum& elem) {
	//std::unique_ptr<elgamal::PublicKey> key_ptr = std::move(absl::WrapUnique(&public_key));
  	ASSIGN_OR_RETURN(ECPoint g, public_key->g.Clone());
	ElGamalEncrypter encrypter = ElGamalEncrypter(ec_group, std::move(public_key));

    ASSIGN_OR_RETURN(ECPoint g_to_m, std::move(g.Mul(elem))); //g^m
    ASSIGN_OR_RETURN(elgamal::Ciphertext now, std::move(encrypter.Encrypt(g_to_m)));
    return std::move(now);
}

}
