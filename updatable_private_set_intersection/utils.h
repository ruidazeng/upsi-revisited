#ifndef UTILS_HPP
#define UTILS_HPP

#include "updatable_private_set_intersection/crypto/context.h"
#include "updatable_private_set_intersection/crypto/ec_commutative_cipher.h"
#include "updatable_private_set_intersection/crypto/paillier.h"

#include <bitset>
#include <vector>
#include <cmath>
#include <set>

namespace updatable_private_set_intersection {

// typedef std::tuple<ECPoint, BigNum> EncryptedElement;
// typedef std::tuple<std::string, int> EncryptedElement;

	typedef std::string BinaryHash;
	
	#define default_node_size 4

	std::string Byte2Binary(std::string const &byte_hash);
	
	template<typename T>
	
	BinaryHash computeBinaryHash(T elem);
	
	BinaryHash generateRandomHash();
	
	void generateRandomHash(int cnt, std::vector<BinaryHash> &hsh);
	
	int find_set_rep(int x, int* f);

}

#endif
