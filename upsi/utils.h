#ifndef UTILS_HPP
#define UTILS_HPP

#include "upsi/crypto/context.h"
#include "upsi/crypto/ec_commutative_cipher.h"
#include "upsi/crypto/elgamal.h"
#include "upsi/crypto/paillier.h"
#include "upsi/network/upsi.pb.h"

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
    #define DEFAULT_STASH_SIZE 89

    #define MAX_SUM 50000

    #define ELEMENT_STR_LENGTH 16

	#define DEBUG 0

    // type of elements in each party's sets
	typedef BigNum Element;

    // type of elements after encryption (i.e., just Ciphertext)
    using elgamal::Ciphertext;

    // type of an element with its associated payload
    typedef std::pair<Element, BigNum> ElementAndPayload;

    // type of an encrypted element with its associated el gamal payload
    typedef std::pair<Ciphertext, Ciphertext> CiphertextAndElGamal;

    // type of an encrypted element with its associated paillier payload
    typedef std::pair<Ciphertext, BigNum> CiphertextAndPaillier;

    // type of where both element and payload are encrypted with paillier
    // (note this is not a std::pair because it would clash with ElementAndPayload)
    class PaillierPair {
        public:
            BigNum first;
            BigNum second;
            PaillierPair(BigNum first, BigNum second) : first(first), second(second) { }
    };

    // protocol functionality options
    enum Functionality { PSI, CA, SUM, SS, DEL };

    // these allow us to have a Functionality command line flag
    bool AbslParseFlag(absl::string_view text, Functionality* func, std::string* err);
    std::string AbslUnparseFlag(Functionality func);


	typedef std::string BinaryHash;

    // TODO: should these be somewhere else?
    template<typename T>
    StatusOr<std::vector<T>> DeserializeCiphertexts(
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
            void lap();
            void print();
        private:
            std::string message;
            std::string color;
            std::chrono::time_point<std::chrono::high_resolution_clock> start;
            std::vector<std::chrono::duration<float>> laps;
            bool using_laps = false;
    };
}

#endif
