#include "absl/flags/flag.h"
#include "absl/flags/parse.h"

#include "crypto/elgamal.h"
#include "crypto/threshold_paillier.h"
#include "crypto_tree.h"
#include "data_util.h"
#include "util/elgamal_key_util.h"
#include "util/elgamal_proto_util.h"
#include "util/proto_util.h"
#include "utils.h"

using namespace upsi;

ABSL_FLAG(bool, keys_only, false, "only generate keys");
ABSL_FLAG(bool, data_only, false, "only generate data");

ABSL_FLAG(std::string, data_dir, "data/", "name of directory for dataset files");
ABSL_FLAG(std::string, out_dir, "out/", "name of directory for keys & trees");

ABSL_FLAG(std::string, p0_fn, "party_zero", "prefix for party one's files");
ABSL_FLAG(std::string, p1_fn, "party_one", "prefix for party zero's files");
ABSL_FLAG(std::string, shared_fn, "shared", "prefix for shared key file");

ABSL_FLAG(int32_t, mod_length, 1536, "bit-length of Paillier modulus");
ABSL_FLAG(int32_t, stat_param, 100, "statistical parameter for Paillier");

ABSL_FLAG(int64_t, p0_size, 50, "total elements in party one's set across all days");
ABSL_FLAG(int64_t, p1_size, 50, "total elements in party zero's set across all days");
ABSL_FLAG(int64_t, shared_size, 25, "total elements in intersection across all days");

ABSL_FLAG(int64_t, days, 10, "number of days the protocol is running for");
ABSL_FLAG(int64_t, per_day, 0, "total elements in both sets each days");
ABSL_FLAG(int64_t, start_size, 0, "size of the initial trees");

ABSL_FLAG(int64_t, max_value, 1000, "maximum number for UPSI-SUM values");

Status GenerateTrees(
    Context* ctx, ECGroup* group, std::vector<Element> data, const std::string& fn
) {
    // read in the keys to encrypt the trees
    ASSIGN_OR_RETURN(
        ElGamalPublicKey elgamal_key,
        ProtoUtils::ReadProtoFromFile<ElGamalPublicKey>(
            absl::GetFlag(FLAGS_out_dir) + absl::GetFlag(FLAGS_shared_fn) + ".epub"
        )
    );

    ElGamalEncrypter elgamal(
        group, elgamal_proto_util::DeserializePublicKey(group, elgamal_key).value()
    );

    // set up the trees
    CryptoTree<Element> plaintext;
    CryptoTree<Ciphertext> encrypted;

    TreeUpdates updates;
    RETURN_IF_ERROR(plaintext.Update(ctx, &elgamal, data, &updates));
    RETURN_IF_ERROR(encrypted.Update(ctx, group, &updates));

    // write them to disk
    PlaintextTree ptree;
    RETURN_IF_ERROR(plaintext.Serialize(&ptree));
    RETURN_IF_ERROR(
        ProtoUtils::WriteProtoToFile(
            ptree, absl::GetFlag(FLAGS_out_dir) + fn + ".tree"
        )
    );

    EncryptedTree etree;
    RETURN_IF_ERROR(encrypted.Serialize(&etree));
    RETURN_IF_ERROR(
        ProtoUtils::WriteProtoToFile(
            etree, absl::GetFlag(FLAGS_out_dir) + fn + "_encrypted.tree"
        )
    );

    std::cout << "[Setup] trees written to: ";
    std::cout << absl::GetFlag(FLAGS_out_dir) << fn << ".tree, ";
    std::cout << absl::GetFlag(FLAGS_out_dir) << fn << "_encrypted.tree" << std::endl;

    std::cout << std::endl;

    return OkStatus();
}

Status GenerateTrees(
    Context* ctx, ECGroup* group, std::vector<ElementAndPayload> data, const std::string& fn
) {
    // read in the keys to encrypt the trees
    ASSIGN_OR_RETURN(
        ElGamalPublicKey elgamal_key,
        ProtoUtils::ReadProtoFromFile<ElGamalPublicKey>(
            absl::GetFlag(FLAGS_out_dir) + absl::GetFlag(FLAGS_shared_fn) + ".epub"
        )
    );

    ElGamalEncrypter elgamal(
        group, elgamal_proto_util::DeserializePublicKey(group, elgamal_key).value()
    );

    ASSIGN_OR_RETURN(
        ThresholdPaillierKey paillier_key,
        ProtoUtils::ReadProtoFromFile<ThresholdPaillierKey>(
            absl::GetFlag(FLAGS_out_dir) + fn + ".pkey"
        )
    );

    ThresholdPaillier paillier(ctx, paillier_key);

    // setup the trees
    CryptoTree<ElementAndPayload> plaintext;
    CryptoTree<CiphertextAndPayload> encrypted;

    TreeUpdates updates;
    RETURN_IF_ERROR(plaintext.Update(ctx, &elgamal, &paillier, data, &updates));
    RETURN_IF_ERROR(encrypted.Update(ctx, group, &updates));

    // write them to disk
    PlaintextTree ptree;
    RETURN_IF_ERROR(plaintext.Serialize(&ptree));
    RETURN_IF_ERROR(
        ProtoUtils::WriteProtoToFile(
            ptree, absl::GetFlag(FLAGS_out_dir) + fn + ".tree"
        )
    );

    EncryptedTree etree;
    RETURN_IF_ERROR(encrypted.Serialize(&etree));
    RETURN_IF_ERROR(
        ProtoUtils::WriteProtoToFile(
            etree, absl::GetFlag(FLAGS_out_dir) + fn + "_encrypted.tree"
        )
    );

    std::cout << "[Setup] trees written to: ";
    std::cout << absl::GetFlag(FLAGS_out_dir) << fn << ".tree, ";
    std::cout << absl::GetFlag(FLAGS_out_dir) << fn << "_encrypted.tree" << std::endl;

    std::cout << std::endl;

    return OkStatus();
}

Status GenerateData(Context* ctx) {

    int64_t total = (
        absl::GetFlag(FLAGS_start_size)
        + (absl::GetFlag(FLAGS_days) * absl::GetFlag(FLAGS_per_day))
    );

    ASSIGN_OR_RETURN(
        auto datasets,
        GenerateRandomDatabases(
            total, total, absl::GetFlag(FLAGS_shared_size), absl::GetFlag(FLAGS_max_value)
        )
    );

    auto party_zero = std::get<1>(datasets);
    auto party_one  = std::get<0>(datasets);

    std::random_device rd;
    std::mt19937 gen(rd());

    std::shuffle(party_one.begin(), party_one.end(), gen);

    // shuffle party zero's elements and values in the same permutation
    std::vector<size_t> permutation(total);
    std::iota(permutation.begin(), permutation.end(), 0);
    std::shuffle(permutation.begin(), permutation.end(), gen);

    std::vector<ElementAndPayload> p0_initial;
    std::vector<Element> p1_initial;
    for (auto i = 0; i < absl::GetFlag(FLAGS_start_size); i++) {
        p0_initial.push_back(std::make_pair(
            ctx->CreateBigNum(std::stoull(party_zero.first[permutation[i]])),
            ctx->CreateBigNum(party_zero.second[permutation[i]])
        ));
        p1_initial.push_back(ctx->CreateBigNum(std::stoull(party_one[i])));
    }

    // write initial trees to out_dir
    if (absl::GetFlag(FLAGS_start_size) > 0) {
        ECGroup group(ECGroup::Create(CURVE_ID, ctx).value());
        RETURN_IF_ERROR(GenerateTrees(ctx, &group, p0_initial, absl::GetFlag(FLAGS_p0_fn)));
        RETURN_IF_ERROR(GenerateTrees(ctx, &group, p1_initial, absl::GetFlag(FLAGS_p1_fn)));
    }

    // split into days
    auto i = absl::GetFlag(FLAGS_start_size);
    for (auto day = 1; day <= absl::GetFlag(FLAGS_days); day++) {
        std::vector<std::string> p0_elements;
        std::vector<int64_t> p0_values;
        std::vector<std::string> p1_elements;
        for (auto j = 0; j < absl::GetFlag(FLAGS_per_day); j++) {
            p0_elements.push_back(party_zero.first[permutation[i]]);
            p0_values.push_back(party_zero.second[permutation[i]]);
            p1_elements.push_back(party_one[i]);
            i++;
        }

        RETURN_IF_ERROR(
            WriteClientDatasetToFile(
                p0_elements, p0_values,
                (
                    absl::GetFlag(FLAGS_data_dir) + absl::GetFlag(FLAGS_p0_fn)
                    + "_" + std::to_string(day) + ".csv"
                )
            )
        );

        RETURN_IF_ERROR(
            WriteServerDatasetToFile(
                p1_elements,
                (
                    absl::GetFlag(FLAGS_data_dir) + absl::GetFlag(FLAGS_p1_fn)
                    + "_" + std::to_string(day) + ".csv"
                )
            )
        );
    }

    // what should the cardinality be
    auto initial_ca = 0;
    auto initial_sum = 0;
    for (auto i = 0; i < absl::GetFlag(FLAGS_start_size); i++) {
        for (auto j = 0; j < absl::GetFlag(FLAGS_start_size); j++) {
            if (party_one[i] == party_zero.first[permutation[j]]) {
                initial_ca++;
                initial_sum += party_zero.second[permutation[j]];
            }
        }
    }

    for (auto i = 0; i < total; i++) {
        if (i % absl::GetFlag(FLAGS_per_day) == 0) std::cout << std::endl;
        std::cout << party_zero.first[permutation[i]] << "\t";
        std::cout << party_one[i] << std::endl;
    }
    std::cout << std::endl;

    std::cout << "[Setup] mock data generated in " << absl::GetFlag(FLAGS_data_dir) << std::endl;
    std::cout << "        P0's total elements : " << total << std::endl;
    std::cout << "        P1's total elements : " << total << std::endl;
    std::cout << "        intersection size   : ";
    std::cout << absl::GetFlag(FLAGS_shared_size) << " - " << initial_ca << " = ";
    std::cout << absl::GetFlag(FLAGS_shared_size) - initial_ca << std::endl;
    std::cout << "        intersection sum    : ";
    std::cout << std::get<2>(datasets) - initial_sum << std::endl;

    return OkStatus();
}

Status GenerateKeys(Context* ctx) {

    RETURN_IF_ERROR(
        elgamal_key_util::GenerateElGamalKeyPair(
            CURVE_ID,
            absl::GetFlag(FLAGS_out_dir) + absl::GetFlag(FLAGS_p0_fn) + ".epub",
            absl::GetFlag(FLAGS_out_dir) + absl::GetFlag(FLAGS_p0_fn) + ".ekey"
        )
    );

    RETURN_IF_ERROR(
        elgamal_key_util::GenerateElGamalKeyPair(
            CURVE_ID,
            absl::GetFlag(FLAGS_out_dir) + absl::GetFlag(FLAGS_p1_fn) + ".epub",
            absl::GetFlag(FLAGS_out_dir) + absl::GetFlag(FLAGS_p1_fn) + ".ekey"
        )
    );

    RETURN_IF_ERROR(
        elgamal_key_util::ComputeJointElGamalPublicKey(
            CURVE_ID,
            {
                absl::GetFlag(FLAGS_out_dir) + absl::GetFlag(FLAGS_p0_fn) + ".epub",
                absl::GetFlag(FLAGS_out_dir) + absl::GetFlag(FLAGS_p1_fn) + ".epub"
            },
            absl::GetFlag(FLAGS_out_dir) + absl::GetFlag(FLAGS_shared_fn) + ".epub"
        )
    );

    RETURN_IF_ERROR(
        GenerateThresholdPaillierKeys(
            ctx,
            absl::GetFlag(FLAGS_mod_length),
            absl::GetFlag(FLAGS_stat_param),
            absl::GetFlag(FLAGS_out_dir) + absl::GetFlag(FLAGS_p0_fn) + ".pkey",
            absl::GetFlag(FLAGS_out_dir) + absl::GetFlag(FLAGS_p1_fn) + ".pkey"
        )
    );

    std::cout << "[Setup] keys generated: ";
    std::cout << absl::GetFlag(FLAGS_out_dir) << absl::GetFlag(FLAGS_p0_fn) << ".ekey, ";
    std::cout << absl::GetFlag(FLAGS_out_dir) << absl::GetFlag(FLAGS_p1_fn) << ".ekey, ";
    std::cout << absl::GetFlag(FLAGS_out_dir) << absl::GetFlag(FLAGS_shared_fn) << ".epub, ";
    std::cout << absl::GetFlag(FLAGS_out_dir) << absl::GetFlag(FLAGS_p0_fn) << ".pkey, ";
    std::cout << absl::GetFlag(FLAGS_out_dir) << absl::GetFlag(FLAGS_p1_fn) << ".pkey";
    std::cout << std::endl;
    return OkStatus();
}

int main(int argc, char** argv) {
    absl::ParseCommandLine(argc, argv);

    Context ctx;

    if (!absl::GetFlag(FLAGS_data_only)) {
        auto status = GenerateKeys(&ctx);
        if (!status.ok()) {
            std::cerr << "[Setup] failure generating keys" << std::endl;
            std::cerr << status << std::endl;
            return 1;
        }
    }

    if (!absl::GetFlag(FLAGS_keys_only)) {
        auto status = GenerateData(&ctx);
        if (!status.ok()) {
            std::cerr << "[Setup] failure generating datasets" << std::endl;
            std::cerr << status << std::endl;
            return 1;
        }
    }
    return 0;
}
