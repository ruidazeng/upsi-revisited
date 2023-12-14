#include "upsi/data_util.h"
#include "upsi/util/elgamal_proto_util.h"
#include "upsi/util/proto_util.h"
#include "upsi/crypto_tree.h"

using namespace upsi;

Status test() {
    Context ctx;
    ECGroup group(ECGroup::Create(CURVE_ID, &ctx).value());

    ASSIGN_OR_RETURN(
        auto raw_data,
        ReadClientDatasetFromFile("data/party_zero_1.csv", &ctx)
    );

    std::vector<std::pair<BigNum, BigNum>> data;
    for (size_t i = 0; i < raw_data.first.size() && i < 2; i++) {
        data.push_back(std::make_pair(raw_data.first[i], raw_data.second[i]));
    }

    ASSIGN_OR_RETURN(
        ElGamalPublicKey epk,
        ProtoUtils::ReadProtoFromFile<ElGamalPublicKey>("out/shared.epub")
    );

    ASSIGN_OR_RETURN(
        ThresholdPaillierKey psk,
        ProtoUtils::ReadProtoFromFile<ThresholdPaillierKey>("out/party_zero.pkey")
    );

    ThresholdPaillier paillier(&ctx, psk);

    ElGamalEncrypter encrypter(
        &group, elgamal_proto_util::DeserializePublicKey(&group, epk).value()
    );

    CryptoTree<ElementAndPayload> plaintext;
    CryptoTree<CiphertextAndPayload> encrypted;

    TreeUpdates updates;
    RETURN_IF_ERROR(plaintext.Update(&ctx, &encrypter, &paillier, data, &updates));
    RETURN_IF_ERROR(encrypted.Update(&ctx, &group, &updates));


    PlaintextTree ptree;
    RETURN_IF_ERROR(plaintext.Serialize(&ptree));
    RETURN_IF_ERROR(
        ProtoUtils::WriteProtoToFile(ptree, "party_one.ptree")
    );

    EncryptedTree etree;
    RETURN_IF_ERROR(encrypted.Serialize(&etree));
    RETURN_IF_ERROR(
        ProtoUtils::WriteProtoToFile(etree, "party_one.etree")
    );

    ASSIGN_OR_RETURN(
        EncryptedTree read,
        ProtoUtils::ReadProtoFromFile<EncryptedTree>("party_one.etree")
    );

    CryptoTree<Ciphertext> recovered;
    recovered.Load(read, &ctx, &group);

    RETURN_IF_ERROR(encrypted.Print());
    std::cout << std::endl;
    RETURN_IF_ERROR(recovered.Print());

    return OkStatus();
}

int main(int argc, char** argv) {
    Status status = test();

    if (!status.ok()) {
        std::cerr << status << std::endl;
        return 1;
    } else {
        return 0;
    }
}
