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

StatusOr<std::vector<Ciphertext>> DeserializeCiphertexts(
    const google::protobuf::RepeatedPtrField<EncryptedElement> serialized,
    Context* ctx,
    ECGroup* group
) {
    std::vector<Ciphertext> ciphertexts;
    for (const EncryptedElement& element : serialized) {
        if (!element.has_no_payload()) {
            return InvalidArgumentError(
                "[Utils] attempting to parse message with a payload"
            );
        }
        ASSIGN_OR_RETURN(
            Ciphertext ciphertext,
            elgamal_proto_util::DeserializeCiphertext(group, element.no_payload().element())
        );
        ciphertexts.push_back(std::move(ciphertext));
    }
    return ciphertexts;
}

StatusOr<std::vector<std::pair<Ciphertext, Ciphertext>>> DeserializeCiphertextAndElGamals(
    const google::protobuf::RepeatedPtrField<EncryptedElement> serialized,
    ECGroup* group
) {
    std::vector<std::pair<Ciphertext, Ciphertext>> ciphertexts;
    for (const EncryptedElement& element : serialized) {
        if (!element.has_elgamal()) {
            return InvalidArgumentError(
                "[Utils] attempting to parse message without El Gamal payload"
            );
        }
        ASSIGN_OR_RETURN(
            Ciphertext ciphertext,
            elgamal_proto_util::DeserializeCiphertext(group, element.elgamal().element())
        );
        ASSIGN_OR_RETURN(
            Ciphertext payload,
            elgamal_proto_util::DeserializeCiphertext(group, element.elgamal().payload())
        );
        ciphertexts.push_back(std::make_pair(
            std::move(ciphertext), std::move(payload)
        ));
    }
    return ciphertexts;
}

StatusOr<std::vector<CiphertextAndPayload>> DeserializeCiphertextAndPayloads(
    const google::protobuf::RepeatedPtrField<EncryptedElement> serialized,
    Context* ctx,
    ECGroup* group
) {
    std::vector<CiphertextAndPayload> ciphertexts;
    for (const EncryptedElement& element : serialized) {
        if (!element.has_paillier()) {
            return InvalidArgumentError(
                "[Utils] attempting to parse message without Paillier payload"
            );
        }

        ASSIGN_OR_RETURN(
            Ciphertext ciphertext,
            elgamal_proto_util::DeserializeCiphertext(group, element.paillier().element())
        );
        ciphertexts.push_back(
            std::make_pair(
                std::move(ciphertext),
                ctx->CreateBigNum(element.paillier().payload())
            )
        );
    }
    return ciphertexts;
}

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


template<>
BinaryHash computeBinaryHash(Ciphertext &elem) {
    throw std::runtime_error("[Utils] trying to hash a ciphertext");
}

////////////////////////////////////////////////////////////////////////////////
// ELEMENT COPY
////////////////////////////////////////////////////////////////////////////////
template<>
Ciphertext elementCopy(const Ciphertext &elem) {
	Ciphertext rs = elgamal::CloneCiphertext(elem).value();
	return rs;
}

template<>
ElementAndPayload elementCopy(const ElementAndPayload& elem) {
    return elem;
}

template<>
Element elementCopy(const Element& elem) {
	Element copy(elem);
	return copy;
}

template<>
CiphertextAndPayload elementCopy(const CiphertextAndPayload& elem) {
	Ciphertext copy = elgamal::CloneCiphertext(std::get<0>(elem)).value();
    return std::make_pair(std::move(copy), std::get<1>(elem));
}

////////////////////////////////////////////////////////////////////////////////

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

Element GetRandomPadElement(Context* ctx) {
    return ctx->CreateBigNum(NumericString2uint(
        GetRandomNumericString(ELEMENT_STR_LENGTH, true)
    ));
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
