#ifndef UTILS_HPP
#define UTILS_HPP

#include "upsi/crypto/context.h"
#include "upsi/crypto/elgamal.h"
#include "upsi/crypto/ec_commutative_cipher.h"
#include "upsi/crypto/paillier.h"

#include <bitset>
#include <vector>
#include <cmath>
#include <set>
#include <iostream>
//#include <strstream>
#include <sstream>
#include <algorithm>
#include <iterator>
#include <memory>
#include <string>
#include <utility>
#include <random>

namespace upsi {

    #define CURVE_ID NID_X9_62_prime256v1
	#define default_node_size 4

	typedef elgamal::Ciphertext Encrypted_UPSI_Element;
	typedef std::string UPSI_Element;

	typedef std::string BinaryHash;


    using elgamal::Ciphertext;

    /**
     * for a group with generator g, gives g^m
     */
    StatusOr<ECPoint> exponentiate(ECGroup* group, const BigNum& m);

	std::string Byte2Binary(const std::string &byte_hash);

	template<typename T>
	BinaryHash computeBinaryHash(T &elem);


	template<typename T>
	T elementCopy(const T &elem);

	BinaryHash generateRandomHash();

	void generateRandomHash(int cnt, std::vector<std::string> &hsh);

	StatusOr<elgamal::Ciphertext> elgamalEncrypt(const ECGroup* ec_group, std::unique_ptr<elgamal::PublicKey> public_key, const BigNum& elem);

	int64_t NumericString2uint(const std::string &str);


	std::string GetRandomNumericString(size_t length);
}

#endif
