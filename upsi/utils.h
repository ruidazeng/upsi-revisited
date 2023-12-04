#ifndef UTILS_HPP
#define UTILS_HPP

#include "upsi/crypto/context.h"
#include "upsi/crypto/elgamal.h"
#include "upsi/crypto/ec_commutative_cipher.h"
#include "upsi/crypto/paillier.h"

#include <algorithm>
#include <bitset>
#include <chrono>
#include <cmath>
#include <iostream>
#include <iterator>
#include <memory>
#include <ostream>
#include <random>
#include <set>
#include <sstream>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

// for printing to the command line in colors
#define RED    "\033[0;31m"
#define GREEN  "\033[0;32m"
#define YELLOW "\033[0;33m"
#define BLUE   "\033[0;34m"
#define CYAN   "\033[0;36m"
#define WHITE  "\033[0;37m"
#define RESET  "\033[0m"

namespace upsi {

    #define CURVE_ID NID_X9_62_prime256v1
	#define DEFAULT_NODE_SIZE 4

    #define ELEMENT_STR_LENGTH 32

	#define DEBUG 1

    // type of elements in each party's sets
	typedef BigNum Element;

    // type of elements after encryption (i.e., just Ciphertext)
    using elgamal::Ciphertext;

    // type of an element with its associated payload
    typedef std::pair<Element, BigNum> ElementAndPayload;

    // type of an encrypted element with its (also encrypted) associated payload
    typedef std::pair<Ciphertext, BigNum> CiphertextAndPayload;

    // protocol functionality options
    enum Functionality { PSI, CA, SUM, SS };


	typedef std::string BinaryHash;

    StatusOr<std::vector<CiphertextAndPayload>> DeserializeCandidates(
        const google::protobuf::RepeatedPtrField<EncryptedElement> serialized,
        Context* ctx,
        ECGroup* group
    );

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

	std::string GetRandomNumericString(size_t length, bool padding);
    std::string GetRandomSetElement();
    Element GetRandomPadElement(Context* ctx);

    /**
     * class to unify time benchmarking
     */
    class Timer {
        public:
            Timer(std::string msg, std::string color = WHITE);
            void stop();
        private:
            std::string message;
            std::string color;
            std::chrono::time_point<std::chrono::high_resolution_clock> start;
    };
}

#endif
