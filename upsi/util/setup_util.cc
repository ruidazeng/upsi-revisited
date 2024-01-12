#include "upsi/util/setup_util.h"

#include <iostream>
#include <system_error>

#include "absl/status/status.h"
#include "upsi/crypto/threshold_paillier.h"
#include "upsi/crypto_tree.h"
#include "upsi/data_util.h"
#include "upsi/util/elgamal_key_util.h"
#include "upsi/util/elgamal_proto_util.h"
#include "upsi/util/proto_util.h"
#include "upsi/util/status.inc"
#include "upsi/utils.h"

namespace upsi {

Status GenerateKeys(
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

Status GenerateData(
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
    std::cout << "[Setup] generating mock data" << std::flush;
    uint32_t total = start_size + (days * daily_size);

    // if shared_size isn't specified, just choose a large enough intersection
    //  such that the daily output will be non-zero with high probability
    if (shared_size < 0) { shared_size = total / 8; }

    ASSIGN_OR_RETURN(
        auto datasets,
        GenerateRandomDatabases(total, total, shared_size, max_value)
    );
    std::cout << "." << std::flush;

    auto party_zero = std::get<1>(datasets);
    auto party_one  = std::get<0>(datasets);

    // shuffle so all the shared elements aren't upfront
    std::random_device rd;
    std::mt19937 gen(rd());
    std::shuffle(party_one.begin(), party_one.end(), gen);
    std::cout << "." << std::flush;

    // shuffle party zero's elements and values in the same permutation
    std::vector<size_t> permutation(total);
    std::iota(permutation.begin(), permutation.end(), 0);
    std::shuffle(permutation.begin(), permutation.end(), gen);
    std::cout << "." << std::flush;

    std::vector<ElementAndPayload> p0_initial;
    std::vector<Element> p1_initial;
    for (uint32_t i = 0; i < start_size; i++) {
        p0_initial.push_back(std::make_pair(
            ctx->CreateBigNum(std::stoull(party_zero.first[permutation[i]])),
            ctx->CreateBigNum(party_zero.second[permutation[i]])
        ));
        p1_initial.push_back(ctx->CreateBigNum(std::stoull(party_one[i])));
    }
    std::cout << " done" << std::endl;

    if (start_size > 0) {
        std::cout << "[Setup] writing initial trees" << std::flush;
        ECGroup group(ECGroup::Create(CURVE_ID, ctx).value());
        RETURN_IF_ERROR(
            GenerateTrees(
                ctx, &group, p0_initial, p0_key_dir, p0_dir, p1_dir, func == Functionality::SS
            )
        );
        std::cout << ".." << std::flush;
        RETURN_IF_ERROR(GenerateTrees(ctx, &group, p1_initial, p1_key_dir, p1_dir, p0_dir));
        std::cout << " done" << std::endl;
    }

    // split into days
    uint32_t i = start_size;
    for (uint32_t day = 1; day <= days; day++) {
        std::vector<std::string> p0_elements;
        std::vector<int64_t> p0_values;
        std::vector<std::string> p1_elements;
        for (uint32_t j = 0; j < daily_size; j++) {
            p0_elements.push_back(party_zero.first[permutation[i]]);
            p0_values.push_back(party_zero.second[permutation[i]]);
            p1_elements.push_back(party_one[i]);
            i++;
        }

        RETURN_IF_ERROR(
            WriteClientDatasetToFile(
                p0_elements, p0_values, p0_dir + std::to_string(day) + ".csv"
            )
        );

        RETURN_IF_ERROR(
            WriteServerDatasetToFile(
                p1_elements, p1_dir + std::to_string(day) + ".csv"
            )
        );
    }

    if (!expected) { return OkStatus(); }

    // calculate what the running cardinality / sum is as of day 1
    auto initial_ca = 0;
    auto initial_sum = 0;
    for (uint32_t i = 0; i < start_size; i++) {
        for (uint32_t j = 0; j < start_size; j++) {
            if (party_one[i] == party_zero.first[permutation[j]]) {
                initial_ca++;
                initial_sum += party_zero.second[permutation[j]];
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
    bool use_paillier
) {
    // read in the keys to encrypt the trees
    ASSIGN_OR_RETURN(auto elgamal, GetElGamal(key_dir, group));

    if (use_paillier) {
        std::cout << "[Debug] using Paillier" << std::endl;
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
    } else {
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
