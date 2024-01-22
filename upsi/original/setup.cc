#include "absl/flags/flag.h"
#include "absl/flags/parse.h"

#include "upsi/crypto/elgamal.h"
#include "upsi/crypto/threshold_paillier.h"
#include "upsi/crypto_tree.h"
#include "upsi/util/data_util.h"
#include "upsi/util/elgamal_key_util.h"
#include "upsi/util/elgamal_proto_util.h"
#include "upsi/util/proto_util.h"
#include "upsi/util/setup_util.h"
#include "upsi/utils.h"

using namespace upsi;

ABSL_FLAG(bool, keys, true, "generate new encryption keys");
ABSL_FLAG(bool, data, true, "generate the dataset");

ABSL_FLAG(std::string, data_dir, "data/", "name of directory for dataset files");
ABSL_FLAG(std::string, out_dir, "out/", "name of directory for keys & trees");

ABSL_FLAG(std::string, p0_fn, "party_zero", "prefix for party one's files");
ABSL_FLAG(std::string, p1_fn, "party_one", "prefix for party zero's files");
ABSL_FLAG(std::string, shared_fn, "shared", "prefix for shared key file");

ABSL_FLAG(uint32_t, days, 10, "number of days the protocol is running for");

ABSL_FLAG(uint32_t, daily_size, 64, "total elements in each set on each day");
ABSL_FLAG(uint32_t, start_size, 0, "size of the initial trees");
ABSL_FLAG(int32_t, shared_size, -1, "total elements in intersection across all days");

ABSL_FLAG(int32_t, max_value, 100, "maximum number for UPSI-SUM values");

// this only matters for secret sharing which requires paillier encryption on the trees
ABSL_FLAG(Functionality, func, Functionality::CA, "which functionality to prepare for");

ABSL_FLAG(bool, expected, true, "compute expected cardinality and sum");

Status WriteHX(Context* ctx, ECGroup* group, const Dataset& p0_tree) {

    ASSIGN_OR_RETURN(
        ElGamalSecretKey sk0,
        ProtoUtils::ReadProtoFromFile<ElGamalSecretKey>(
            absl::GetFlag(FLAGS_out_dir) + "p0/elgamal.key"
        )
    );

    ElGamalDecrypter p0(ctx, elgamal_proto_util::DeserializePrivateKey(ctx, sk0).value());

    ASSIGN_OR_RETURN(
        ElGamalSecretKey sk1,
        ProtoUtils::ReadProtoFromFile<ElGamalSecretKey>(
            absl::GetFlag(FLAGS_out_dir) + "p1/elgamal.key"
        )
    );

    ElGamalDecrypter p1(ctx, elgamal_proto_util::DeserializePrivateKey(ctx, sk1).value());

    OPRF oprf;
    for (const BigNum& x : p0_tree.Elements()) {
        ASSIGN_OR_RETURN(ECPoint hx, group->GetPointByHashingToCurveSha256(x.ToBytes()));
        ASSIGN_OR_RETURN(ECPoint hx_to_a, hx.Mul(p0.getPrivateKey()->x));
        ASSIGN_OR_RETURN(ECPoint hx_to_ab, hx_to_a.Mul(p1.getPrivateKey()->x));
        ASSIGN_OR_RETURN(auto serialized, hx_to_ab.ToBytesUnCompressed());
        auto kv = oprf.add_kv();
        kv->set_element(x.ToDecimalString());
        kv->set_output(serialized);
    }

    RETURN_IF_ERROR(
        ProtoUtils::WriteProtoToFile(oprf, absl::GetFlag(FLAGS_data_dir) + "p0/elements.ec")
    );
    return OkStatus();
}

Status GenerateData(Context* ctx) {
    std::cout << "[Setup] generating mock data" << std::endl;

    uint32_t days = absl::GetFlag(FLAGS_days);
    uint32_t daily_size = absl::GetFlag(FLAGS_daily_size);
    uint32_t start_size = absl::GetFlag(FLAGS_start_size);
    uint32_t total = start_size + (days * daily_size);

    // if shared_size isn't specified, just choose a large enough intersection
    //  such that the daily output will be non-zero with high probability
    int32_t shared_size = absl::GetFlag(FLAGS_shared_size);
    if (shared_size < 0) { shared_size = total / 8; }

    // where to find the setup files
    std::string p0_key_dir = absl::GetFlag(FLAGS_out_dir) + "p0/";
    std::string p1_key_dir = absl::GetFlag(FLAGS_out_dir) + "p1/";
    std::string p0_dir = absl::GetFlag(FLAGS_data_dir) + "p0/";
    std::string p1_dir = absl::GetFlag(FLAGS_data_dir) + "p1/";

    auto [ p0_tree, p0_days, p1_tree, p1_days, sum ] = GenerateAddOnlySets(
        ctx, days, daily_size, start_size, shared_size, absl::GetFlag(FLAGS_max_value)
    );

    for (size_t day = 0; day < days; day++) {
        RETURN_IF_ERROR(
            p0_days[day].Write(p0_dir + std::to_string(day + 1) + ".csv")
        );
        RETURN_IF_ERROR(
            p1_days[day].Write(p1_dir + std::to_string(day + 1) + ".csv")
        );
    }

    if (start_size > 0) {
        std::cout << "[Setup] writing initial tree" << std::flush;
        ECGroup group(ECGroup::Create(CURVE_ID, ctx).value());
        RETURN_IF_ERROR(
            GenerateTrees(
                ctx, &group, p1_tree.Elements(), p1_key_dir, p1_dir, p0_dir, "elgamal.pub"
            )
        );
        std::cout << "." << std::flush;
        RETURN_IF_ERROR(WriteHX(ctx, &group, p0_tree));
        std::cout << ".. done" << std::endl;

        if (!absl::GetFlag(FLAGS_expected)) { return OkStatus(); }

        // calculate what the cardinality should be
        size_t initial_ca = 0;
        for (const std::string& p0_elem : p0_tree.elements) {
            for (const std::string& p1_elem : p1_tree.elements) {
                if (p0_elem == p1_elem) {
                    initial_ca++;
                }
            }
        }

        std::cout << "[Setup] expected output:" << std::endl;
        std::cout << "        intersection size = " << shared_size - initial_ca << std::endl;
    } else {
        std::cout << "[Setup] expected output:" << std::endl;
        std::cout << "        intersection size = " << shared_size << std::endl;
    }

    return OkStatus();
}

int main(int argc, char** argv) {
    absl::ParseCommandLine(argc, argv);

    Context ctx;

    if (absl::GetFlag(FLAGS_keys)) {
        auto status = GenerateElGamalKeys(
            &ctx,
            absl::GetFlag(FLAGS_out_dir) + "p0/",
            absl::GetFlag(FLAGS_out_dir) + "p1/"
        );
        if (!status.ok()) {
            std::cerr << "[Setup] failure generating keys" << std::endl;
            std::cerr << status << std::endl;
            return 1;
        }
    }

    if (absl::GetFlag(FLAGS_data)) {
        auto status = GenerateData(&ctx);
        if (!status.ok()) {
            std::cerr << "[Setup] failure generating datasets" << std::endl;
            std::cerr << status << std::endl;
            return 1;
        }
    }
    return 0;
}
