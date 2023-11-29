#ifndef UTILS_HPP
#define UTILS_HPP

#include "updatable_private_set_intersection/crypto/context.h"
#include "updatable_private_set_intersection/crypto/elgamal.h"
#include "updatable_private_set_intersection/crypto/ec_commutative_cipher.h"
#include "updatable_private_set_intersection/crypto/paillier.h"

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

namespace updatable_private_set_intersection {

	typedef elgamal::Ciphertext Encrypted_UPSI_Element;
	typedef std::string UPSI_Element;

	typedef std::string BinaryHash;
	
	#define default_node_size 4

	std::string Byte2Binary(std::string const &byte_hash);
	
	template<typename T>
	BinaryHash computeBinaryHash(T &elem);
	
	
	template<typename T>
	T elementCopy(const T &elem);
	
	BinaryHash generateRandomHash();
	
	void generateRandomHash(int cnt, std::vector<BinaryHash> &hsh);
	
	StatusOr<elgamal::Ciphertext> elgamalEncrypt(const ECGroup* ec_group, std::unique_ptr<elgamal::PublicKey> public_key, const BigNum& elem);
}

#endif
