#include "upsi/util/setup_util.h"

#include <iostream>
#include <system_error>

#include "absl/status/status.h"
#include "upsi/crypto/paillier.pb.h"
#include "upsi/crypto/threshold_paillier.h"
#include "upsi/crypto_tree.h"
#include "upsi/util/data_util.h"
#include "upsi/util/elgamal_key_util.h"
#include "upsi/util/elgamal_proto_util.h"
#include "upsi/util/proto_util.h"
#include "upsi/util/status.inc"
#include "upsi/utils.h"

namespace upsi {

Status GenerateThresholdKeys(
    Context* ctx,
    std::string p0_dir,
    std::string p1_dir,
    int32_t mod_length,
    int32_t stat_param
) {
    std::cout << "[Setup] generating keys" << std::flush;

    RETURN_IF_ERROR(
        elgamal_key_util::GenerateElGamalKeyPair(
            CURVE_ID, p0_dir + "/elgamal.pub", p0_dir + "/elgamal.key"
        )
    );
    std::cout << "." << std::flush;

    RETURN_IF_ERROR(
        elgamal_key_util::GenerateElGamalKeyPair(
            CURVE_ID, p1_dir + "/elgamal.pub", p1_dir + "/elgamal.key"
        )
    );
    std::cout << "." << std::flush;

    RETURN_IF_ERROR(
        elgamal_key_util::ComputeJointElGamalPublicKey(
            CURVE_ID,
            { p0_dir + "elgamal.pub", p1_dir + "elgamal.pub" },
            p0_dir + "shared.pub"
        )
    );
    std::cout << "." << std::flush;

    // could just copy the `p0_dir/shared.pub` file but C++ doesn't have an
    // easy file copy method before C++17
    RETURN_IF_ERROR(
        elgamal_key_util::ComputeJointElGamalPublicKey(
            CURVE_ID,
            { p0_dir + "elgamal.pub", p1_dir + "elgamal.pub" },
            p1_dir + "shared.pub"
        )
    );
    std::cout << "." << std::flush;

    RETURN_IF_ERROR(
        GenerateThresholdPaillierKeys(
            ctx, mod_length, stat_param, p0_dir + "paillier.key", p1_dir + "paillier.key"
        )
    );
    std::cout << "." << std::flush;

    // a bit of visual flare
    std::string p0_spacing(p0_dir.length() - 1, ' ');
    std::string p1_spacing(p0_dir.length() - 1, ' ');

    // report which files were created
    std::cout << " done" << std::endl;
    std::cout << "        " << p0_dir << "elgamal.key" << std::endl;
    std::cout << "        " << p0_spacing << "/shared.pub" << std::endl;
    std::cout << "        " << p0_spacing << "/paillier.key" << std::endl;
    std::cout << "        " << p1_dir << "elgamal.key" << std::endl;
    std::cout << "        " << p1_spacing << "/shared.pub" << std::endl;
    std::cout << "        " << p1_spacing << "/paillier.key" << std::endl;
    std::cout << std::endl;
    return OkStatus();
}

Status GeneratePaillierKeys(
    Context* ctx,
    std::string p0_dir,
    std::string p1_dir,
    int32_t mod_length,
    int32_t stat_param
) {
    std::cout << "[Setup] generating keys" << std::flush;

    // TODO (max): should we try different `s` parameters?
    ASSIGN_OR_RETURN(auto p0, GeneratePaillierKeyPair(ctx, mod_length, 1));
    std::cout << "." << std::flush;
    ASSIGN_OR_RETURN(auto p1, GeneratePaillierKeyPair(ctx, mod_length, 1));
    std::cout << "." << std::flush;

    RETURN_IF_ERROR(
        ProtoUtils::WriteProtoToFile(p0.first, p1_dir + "paillier.pub")
    );

    RETURN_IF_ERROR(
        ProtoUtils::WriteProtoToFile(p0.second, p0_dir + "paillier.key")
    );

    RETURN_IF_ERROR(
        ProtoUtils::WriteProtoToFile(p1.first, p0_dir + "paillier.pub")
    );

    RETURN_IF_ERROR(
        ProtoUtils::WriteProtoToFile(p1.second, p1_dir + "paillier.key")
    );

    // a bit of visual flare
    std::string p0_spacing(p0_dir.length() - 1, ' ');
    std::string p1_spacing(p0_dir.length() - 1, ' ');

    std::cout << ". done" << std::endl;
    std::cout << "        " << p0_dir << "paillier.key" << std::endl;
    std::cout << "        " << p0_spacing << "/paillier.pub" << std::endl;
    std::cout << "        " << p1_dir << "paillier.key" << std::endl;
    std::cout << "        " << p1_spacing << "/paillier.pub" << std::endl;
    std::cout << std::endl;

    return OkStatus();
}

StatusOr<std::unique_ptr<ElGamalEncrypter>> GetElGamal(
    const std::string& dir, ECGroup* group
) {
    ASSIGN_OR_RETURN(
        ElGamalPublicKey serial_key,
        ProtoUtils::ReadProtoFromFile<ElGamalPublicKey>(dir + "shared.pub")
    );

    ASSIGN_OR_RETURN(
        std::unique_ptr<elgamal::PublicKey> elgamal_pk,
        elgamal_proto_util::DeserializePublicKey(group, serial_key)
    );

    return std::make_unique<ElGamalEncrypter>(group, std::move(elgamal_pk));
}

template<typename P, typename E>
Status WriteTrees(
    CryptoTree<P>& plaintext,
    const std::string& plaintext_dir,
    CryptoTree<E>& encrypted,
    const std::string& encrypted_dir
) {
    PlaintextTree ptree;
    RETURN_IF_ERROR(plaintext.Serialize(&ptree));
    RETURN_IF_ERROR(
        ProtoUtils::WriteProtoToFile(ptree, plaintext_dir + "plaintext.tree")
    );

    EncryptedTree etree;
    RETURN_IF_ERROR(encrypted.Serialize(&etree));
    RETURN_IF_ERROR(
        ProtoUtils::WriteProtoToFile(etree, encrypted_dir + "encrypted.tree")
    );
    return OkStatus();
}

Status GenerateTrees(
    Context* ctx,
    ECGroup* group,
    std::vector<Element> data,
    const std::string& key_dir,
    const std::string& plaintext_dir,
    const std::string& encrypted_dir
) {
    // read in the keys to encrypt the trees
    ASSIGN_OR_RETURN(auto encrypter, GetElGamal(key_dir, group));

    // set up the trees
    CryptoTree<Element> plaintext;
    CryptoTree<Ciphertext> encrypted;

    TreeUpdates updates;
    RETURN_IF_ERROR(plaintext.Update(ctx, encrypter.get(), data, &updates));
    RETURN_IF_ERROR(encrypted.Update(ctx, group, &updates));

    // write them to disk
    RETURN_IF_ERROR(WriteTrees(plaintext, plaintext_dir, encrypted, encrypted_dir));
    return OkStatus();
}

Status GenerateTrees(
    Context* ctx,
    ECGroup* group,
    std::vector<ElementAndPayload> data,
    const std::string& key_dir,
    const std::string& plaintext_dir,
    const std::string& encrypted_dir,
    Functionality func
) {
    if (func == Functionality::SS) {
        ASSIGN_OR_RETURN(auto elgamal, GetElGamal(key_dir, group));

        ASSIGN_OR_RETURN(
            ThresholdPaillierKey paillier_key,
            ProtoUtils::ReadProtoFromFile<ThresholdPaillierKey>(key_dir + "paillier.key")
        );

        ThresholdPaillier paillier(ctx, paillier_key);

        CryptoTree<ElementAndPayload> plaintext;
        CryptoTree<CiphertextAndPaillier> encrypted;

        TreeUpdates updates;
        RETURN_IF_ERROR(plaintext.Update(ctx, elgamal.get(), &paillier, data, &updates));
        RETURN_IF_ERROR(encrypted.Update(ctx, group, &updates));

        RETURN_IF_ERROR(WriteTrees(plaintext, plaintext_dir, encrypted, encrypted_dir));
    } else if (func == Functionality::DEL) {
        ASSIGN_OR_RETURN(
            PaillierPrivateKey paillier_key,
            ProtoUtils::ReadProtoFromFile<PaillierPrivateKey>(key_dir + "paillier.key")
        );

        PrivatePaillier paillier(ctx, paillier_key);

        CryptoTree<ElementAndPayload> plaintext;
        CryptoTree<PaillierPair> encrypted;

        TreeUpdates updates;
        RETURN_IF_ERROR(plaintext.Update(ctx, &paillier, data, &updates));
        RETURN_IF_ERROR(encrypted.Update(ctx, group, &updates));

        RETURN_IF_ERROR(WriteTrees(plaintext, plaintext_dir, encrypted, encrypted_dir));
    } else {
        ASSIGN_OR_RETURN(auto elgamal, GetElGamal(key_dir, group));

        CryptoTree<ElementAndPayload> plaintext;
        CryptoTree<CiphertextAndElGamal> encrypted;

        TreeUpdates updates;
        RETURN_IF_ERROR(plaintext.Update(ctx, elgamal.get(), data, &updates));
        RETURN_IF_ERROR(encrypted.Update(ctx, group, &updates));

        RETURN_IF_ERROR(WriteTrees(plaintext, plaintext_dir, encrypted, encrypted_dir));
    }
    return OkStatus();
}

Status GenerateTrees(
    Context* ctx,
    ECGroup* group,
    const std::vector<Dataset>& data,
    const std::string& key_dir,
    const std::string& plaintext_dir,
    const std::string& encrypted_dir
) {
    ASSIGN_OR_RETURN(
        PaillierPrivateKey paillier_key,
        ProtoUtils::ReadProtoFromFile<PaillierPrivateKey>(key_dir + "paillier.key")
    );

    PrivatePaillier paillier(ctx, paillier_key);

    // because we are allowing single additions and deletions, node size must be doubled
    CryptoTree<ElementAndPayload> plaintext(DEFAULT_STASH_SIZE, DEFAULT_NODE_SIZE * 2);
    CryptoTree<PaillierPair> encrypted(DEFAULT_STASH_SIZE, DEFAULT_NODE_SIZE * 2);

    for (size_t day = 0; day < data.size(); day++) {
        TreeUpdates updates;
        std::vector<ElementAndPayload> daily = data[day].ElementsAndValues();
        RETURN_IF_ERROR(plaintext.Update(ctx, &paillier, daily, &updates));
        RETURN_IF_ERROR(encrypted.Update(ctx, group, &updates));
    }

    RETURN_IF_ERROR(WriteTrees(plaintext, plaintext_dir, encrypted, encrypted_dir));

    return OkStatus();
}


} // namespace
