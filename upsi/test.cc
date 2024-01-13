#include "absl/status/status.h"

#include "upsi/crypto/elgamal.h"
#include "upsi/crypto/threshold_paillier.h"
#include "upsi/util/elgamal_proto_util.h"
#include "upsi/util/proto_util.h"
#include "upsi/utils.h"

using namespace upsi;

// number of elements to test el gamal operations on
#define ELGAMAL_SIZE 10000

// limit for el gamal exponential decryption
#define EXP_LIMIT 10000

// number of elements to test paillier operations on
#define PAILLIER_SIZE 1000


Status TestElGamal() {
    std::cout << ">> TESTING EL GAMAL (" << ELGAMAL_SIZE << " ELEMENTS) <<" << std::endl;

    Context ctx;

    ASSIGN_OR_RETURN(ECGroup group, ECGroup::Create(CURVE_ID, &ctx));

    ASSIGN_OR_RETURN(auto epk, ProtoUtils::ReadProtoFromFile<ElGamalPublicKey>("out/shared.epub"));

    ASSIGN_OR_RETURN(auto public_key, elgamal_proto_util::DeserializePublicKey(&group, epk));

    ASSIGN_OR_RETURN(
        auto esk0, ProtoUtils::ReadProtoFromFile<ElGamalSecretKey>("out/party_one.ekey")
    );
    ElGamalDecrypter partialer = ElGamalDecrypter(
        &ctx, elgamal_proto_util::DeserializePrivateKey(&ctx, esk0).value()
    );

    ASSIGN_OR_RETURN(
        auto esk1, ProtoUtils::ReadProtoFromFile<ElGamalSecretKey>("out/party_zero.ekey")
    );

    ElGamalDecrypter decrypter = ElGamalDecrypter(
        &ctx, elgamal_proto_util::DeserializePrivateKey(&ctx, esk1).value()
    );

    Timer expsetup("[Test] Exp ElGamal Setup");
    RETURN_IF_ERROR(decrypter.InitDecryptExp(public_key.get(), EXP_LIMIT));
    expsetup.stop();

    ElGamalEncrypter encrypter(&group, std::move(public_key));

    std::vector<Element> elements;
    for (auto i = 0; i < ELGAMAL_SIZE; i++) {
        elements.push_back(ctx.CreateBigNum(std::stoull(GetRandomSetElement())));
    }

    std::vector<BigNum> values;
    for (auto i = 0; i < ELGAMAL_SIZE; i++) {
        values.push_back(ctx.GenerateRandLessThan(ctx.CreateBigNum(EXP_LIMIT)));
    }

    Timer encrypt("[Test] ElGamal Encrypt");
    std::vector<Ciphertext> ciphertexts;
    for (const Element& element : elements) {
        ASSIGN_OR_RETURN(auto ciphertext, encrypter.Encrypt(element));
        ciphertexts.push_back(std::move(ciphertext));
    }
    encrypt.stop();

    Timer rerand("[Test] ElGamal Randomize");
    for (size_t i = 0; i < ciphertexts.size(); i++) {
        ASSIGN_OR_RETURN(ciphertexts[i], encrypter.ReRandomize(ciphertexts[i]));
    }
    rerand.stop();

    Timer add("[Test] ElGamal Addition");
    for (size_t i = 0; i < ciphertexts.size() - 1; i++) {
        ASSIGN_OR_RETURN(ciphertexts[i], elgamal::Mul(ciphertexts[i], ciphertexts[i+1]));
    }
    add.stop();

    Timer invert("[Test] ElGamal Invert");
    for (size_t i = 0; i < ciphertexts.size(); i++) {
        ASSIGN_OR_RETURN(ciphertexts[i], elgamal::Invert(ciphertexts[i]));
    }
    invert.stop();

    Timer mask("[Test] ElGamal Masking");
    for (size_t i = 0; i < ciphertexts.size(); i++) {
        BigNum mask = encrypter.CreateRandomMask();
        ASSIGN_OR_RETURN(ciphertexts[i], elgamal::Exp(ciphertexts[i], mask));
    }
    mask.stop();

    Timer partdec("[Test] ElGamal PartDec");
    std::vector<Ciphertext> partials;
    for (size_t i = 0; i < ciphertexts.size(); i++) {
        ASSIGN_OR_RETURN(auto partial, partialer.PartialDecrypt(ciphertexts[i]));
        partials.push_back(std::move(partial));
    }
    partdec.stop();

    Timer dec("[Test] ElGamal Decrypt");
    std::vector<ECPoint> recovered;
    for (size_t i = 0; i < ciphertexts.size(); i++) {
        ASSIGN_OR_RETURN(auto decrypted, decrypter.Decrypt(partials[i]));
        recovered.push_back(std::move(decrypted));
    }
    dec.stop();

    Timer vencrypt("[Test] ExpElGamal Encrypt");
    std::vector<Ciphertext> value_ciphers;
    for (const Element& value : values) {
        ASSIGN_OR_RETURN(auto ciphertext, encrypter.Encrypt(value));
        value_ciphers.push_back(std::move(ciphertext));
    }
    vencrypt.stop();

    Timer vparts("[Test] ExpElGamal PartDec");
    std::vector<Ciphertext> value_parts;
    for (size_t i = 0; i < value_ciphers.size(); i++) {
        ASSIGN_OR_RETURN(auto partial, partialer.PartialDecrypt(value_ciphers[i]));
        value_parts.push_back(std::move(partial));
    }
    vparts.stop();

    Timer vdec("[Test] ElGamal Decrypt");
    std::vector<BigNum> value_decs;
    for (size_t i = 0; i < value_parts.size(); i++) {
        ASSIGN_OR_RETURN(auto decrypted, decrypter.DecryptExp(value_parts[i]));
        value_decs.push_back(decrypted);
        if (value_decs[i] != values[i]) {
            std::cerr << "[Test] failed to correctly decrypt @ " << i << std::endl;
        }
    }
    vdec.stop();

    return OkStatus();
}

Status TestPaillier() {
    std::cout << ">> TESTING PAILLIER  (" << PAILLIER_SIZE << " ELEMENTS) <<" << std::endl;

    Context ctx;

    ASSIGN_OR_RETURN(
        auto sk0, ProtoUtils::ReadProtoFromFile<ThresholdPaillierKey>("out/party_zero.pkey")
    );
    ThresholdPaillier zero(&ctx, sk0);

    ASSIGN_OR_RETURN(
        auto sk1, ProtoUtils::ReadProtoFromFile<ThresholdPaillierKey>("out/party_one.pkey")
    );
    ThresholdPaillier one(&ctx, sk1);

    std::vector<Element> elements;
    for (auto i = 0; i < PAILLIER_SIZE; i++) {
        elements.push_back(ctx.CreateBigNum(std::stoull(GetRandomSetElement())));
    }

    Timer encrypt("[Test] Paillier Encrypt");
    std::vector<BigNum> ciphertexts;
    for (const Element& element : elements) {
        ASSIGN_OR_RETURN(auto ciphertext, zero.Encrypt(element));
        ciphertexts.push_back(std::move(ciphertext));
    }
    encrypt.stop();

    Timer rerand("[Test] Paillier Rerandomize");
    for (size_t i = 1; i < ciphertexts.size(); i++) {
        ASSIGN_OR_RETURN(ciphertexts[i], zero.ReRand(ciphertexts[i]));
    }
    rerand.stop();

    Timer add("[Test] Paillier Addition");
    BigNum sum = ciphertexts[0];
    for (size_t i = 1; i < ciphertexts.size(); i++) {
        sum = zero.Add(sum, ciphertexts[i]);
    }
    add.stop();

    Timer partdec("[Test] Paillier PartDec");
    std::vector<BigNum> partials;
    for (size_t i = 0; i < ciphertexts.size() - 1; i++) {
        ASSIGN_OR_RETURN(auto partial, zero.PartialDecrypt(ciphertexts[i]));
        partials.push_back(std::move(partial));
    }
    partdec.stop();

    Timer dec("[Test] Paillier Decrypt");
    std::vector<BigNum> recovered;
    for (size_t i = 0; i < ciphertexts.size() - 1; i++) {
        ASSIGN_OR_RETURN(auto decrypted, one.Decrypt(ciphertexts[i], partials[i]));
        recovered.push_back(std::move(decrypted));
    }
    dec.stop();

    return OkStatus();
}


int main(int argc, char** argv) {

    auto status = TestElGamal();
    if (!status.ok()) {
        std::cerr << status << std::endl;
        return 1;
    }

    status = TestPaillier();
    if (!status.ok()) {
        std::cerr << status << std::endl;
        return 1;
    }

    return 0;
}
