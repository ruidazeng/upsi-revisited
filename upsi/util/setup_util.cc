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

Status GenerateAdditionData(
    Context* ctx,
    std::string p0_key_dir,
    std::string p1_key_dir,
    std::string p0_dir,
    std::string p1_dir,
    uint32_t days,
    uint32_t start_size,
    uint32_t daily_size,
    int32_t shared_size,
    int32_t max_value,
    Functionality func,
    bool expected
) {
    std::cout << "[Setup] generating mock data" << std::endl;
    uint32_t total = start_size + (days * daily_size);

    // if shared_size isn't specified, just choose a large enough intersection
    //  such that the daily output will be non-zero with high probability
    if (shared_size < 0) { shared_size = total / 8; }

    std::vector<uint32_t> sizes;
    if (start_size > 0) { sizes.push_back(start_size); }
    for (size_t day = 1; day <= days; day++) { sizes.push_back(daily_size); }

    auto datasets = GenerateAddOnlySets(ctx, sizes, shared_size, max_value);

    std::vector<Dataset> party_zero = std::get<0>(datasets);
    std::vector<Dataset> party_one  = std::get<1>(datasets);

    if (start_size > 0) {
        std::cout << "[Setup] writing initial trees" << std::flush;
        ECGroup group(ECGroup::Create(CURVE_ID, ctx).value());
        RETURN_IF_ERROR(
            GenerateTrees(
                ctx, &group, party_zero[0].ElementsAndValues(), p0_key_dir, p0_dir, p1_dir, func
            )
        );
        std::cout << ".." << std::flush;
        RETURN_IF_ERROR(
            GenerateTrees(
                ctx, &group, party_one[0].Elements(), p1_key_dir, p1_dir, p0_dir
            )
        );
        std::cout << " done" << std::endl;

        for (size_t day = 1; day <= days; day++) {
            RETURN_IF_ERROR(
                party_zero[day].Write(p0_dir + std::to_string(day) + ".csv")
            );
            RETURN_IF_ERROR(
                party_one[day].Write(p1_dir + std::to_string(day) + ".csv")
            );
        }
    } else {
        for (size_t day = 0; day < days; day++) {
            RETURN_IF_ERROR(
                party_zero[day].Write(p0_dir + std::to_string(day + 1) + ".csv")
            );
            RETURN_IF_ERROR(
                party_one[day].Write(p1_dir + std::to_string(day + 1) + ".csv")
            );
        }
    }


    if (!expected) { return OkStatus(); }

    // calculate what the running cardinality / sum is as of day 1
    auto initial_ca = 0;
    auto initial_sum = 0;
    if (start_size > 0) {
        for (size_t i = 0; i < party_zero[0].elements.size(); i++) {
            for (size_t j = 0; j < party_one[0].elements.size(); j++) {
                if (party_zero[0].elements[i] == party_one[0].elements[j]) {
                    initial_ca++;
                    initial_sum += party_zero[0].values[i];
                }
            }
        }
    }

    std::cout << "[Setup] expected output:" << std::endl;
    std::cout << "        intersection size = ";
    std::cout << shared_size << " - " << initial_ca << " = ";
    std::cout << shared_size - initial_ca << std::endl;
    std::cout << "        intersection sum  = ";
    std::cout << std::get<2>(datasets) - initial_sum << std::endl;

    if (std::get<2>(datasets) - initial_sum > MAX_SUM && func != Functionality::SS) {
        std::cout << std::endl;
        std::cout << "[WARNING] expected sum larger than maximum sum (=";
        std::cout << MAX_SUM << ")" << std::endl;
    }

    return OkStatus();
}

Status GenerateDeletionData(
    Context* ctx,
    std::string p0_key_dir,
    std::string p1_key_dir,
    std::string p0_dir,
    std::string p1_dir,
    uint32_t days,
    uint32_t start_size,
    uint32_t daily_size,
    int32_t shared_size,
    int32_t max_value,
    bool expected
) {
    std::cout << "[Setup] generating mock data" << std::endl;
    uint32_t total = start_size + (days * daily_size);

    // if shared_size isn't specified, just choose a large enough intersection
    //  such that the daily output will be non-zero with high probability
    if (shared_size < 0) { shared_size = total / 8; }

    std::vector<uint32_t> sizes;
    if (start_size > 0) { sizes.push_back(start_size); }
    for (size_t day = 1; day <= days; day++) { sizes.push_back(daily_size); }

    auto datasets = GenerateDeletionSets(ctx, sizes, shared_size, max_value);

    std::vector<Dataset> party_zero = std::get<0>(datasets);
    std::vector<Dataset> party_one  = std::get<1>(datasets);

    if (start_size > 0) {
        std::cout << "[Setup] writing initial trees" << std::flush;
        ECGroup group(ECGroup::Create(CURVE_ID, ctx).value());
        RETURN_IF_ERROR(
            GenerateTrees(
                ctx, &group, party_zero[0].ElementsAndValues(),
                p0_key_dir, p0_dir, p1_dir, Functionality::DEL
            )
        );
        std::cout << ".." << std::flush;
        RETURN_IF_ERROR(
            GenerateTrees(
                ctx, &group, party_one[0].ElementsAndValues(),
                p1_key_dir, p1_dir, p0_dir, Functionality::DEL
            )
        );
        std::cout << " done" << std::endl;

        for (size_t day = 1; day <= days; day++) {
            RETURN_IF_ERROR(
                party_zero[day].Write(p0_dir + std::to_string(day) + ".csv")
            );
            RETURN_IF_ERROR(
                party_one[day].Write(p1_dir + std::to_string(day) + ".csv")
            );
        }
    } else {
        for (size_t day = 0; day < days; day++) {
            RETURN_IF_ERROR(
                party_zero[day].Write(p0_dir + std::to_string(day + 1) + ".csv")
            );
            RETURN_IF_ERROR(
                party_one[day].Write(p1_dir + std::to_string(day + 1) + ".csv")
            );
        }
    }


    if (!expected) { return OkStatus(); }

    // calculate what the running cardinality / sum is as of day 1
    auto initial_ca = 0;
    auto initial_sum = 0;
    if (start_size > 0) {
        for (size_t i = 0; i < party_zero[0].elements.size(); i++) {
            for (size_t j = 0; j < party_one[0].elements.size(); j++) {
                if (party_zero[0].elements[i] == party_one[0].elements[j]) {
                    initial_ca++;
                    initial_sum += party_zero[0].values[i];
                }
            }
        }
    }

    std::cout << "[Setup] expected output:" << std::endl;
    std::cout << "        intersection size = ";
    std::cout << shared_size << " - " << initial_ca << " = ";
    std::cout << shared_size - initial_ca << std::endl;
    std::cout << "        intersection sum  = ";
    std::cout << std::get<2>(datasets) - initial_sum << std::endl;

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


} // namespace
