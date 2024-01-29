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

ABSL_FLAG(int32_t, mod_length, 1536, "bit-length of Paillier modulus");
ABSL_FLAG(int32_t, stat_param, 100, "statistical parameter for Paillier");

ABSL_FLAG(uint32_t, days, 10, "number of days the protocol is running for");
ABSL_FLAG(uint32_t, daily_size, 10, "total elements in each set on each day");
ABSL_FLAG(uint32_t, start_size, 0, "size of the initial trees");

ABSL_FLAG(upsi::Functionality, func, upsi::Functionality::PSI, "desired protocol functionality");

ABSL_FLAG(int32_t, max_value, 100, "maximum number for UPSI-SUM values");

Status GenerateData(Context* ctx) {
    std::cout << "[Setup] generating mock data" << std::endl;

    uint32_t days = absl::GetFlag(FLAGS_days);
    uint32_t daily_size = absl::GetFlag(FLAGS_daily_size);
    uint32_t start_size = absl::GetFlag(FLAGS_start_size);

    // where to find the setup files
    std::string p0_key_dir = absl::GetFlag(FLAGS_out_dir) + "p0/";
    std::string p1_key_dir = absl::GetFlag(FLAGS_out_dir) + "p1/";
    std::string p0_dir = absl::GetFlag(FLAGS_data_dir) + "p0/";
    std::string p1_dir = absl::GetFlag(FLAGS_data_dir) + "p1/";

    auto [ p0_tree, p0_days, p1_tree, p1_days, sum ] = GenerateDeletionSets(
        ctx, days, daily_size, start_size, absl::GetFlag(FLAGS_max_value),
        absl::GetFlag(FLAGS_func)
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
        std::cout << "[Setup] writing initial trees" << std::flush;
        ECGroup group(ECGroup::Create(CURVE_ID, ctx).value());
        RETURN_IF_ERROR( GenerateTrees(ctx, &group, p0_tree, p0_key_dir, p0_dir, p1_dir));
        std::cout << "." << std::flush;

        RETURN_IF_ERROR(GenerateTrees(ctx, &group, p1_tree, p1_key_dir, p1_dir, p0_dir));
        std::cout << ". done" << std::endl;
    }

    std::cout << "[Setup] expected output = " << sum << std::endl;

    return OkStatus();
}

int main(int argc, char** argv) {
    absl::ParseCommandLine(argc, argv);

    Context ctx;

    if (absl::GetFlag(FLAGS_keys)) {
        auto status = GeneratePaillierKeys(
            &ctx,
            absl::GetFlag(FLAGS_out_dir) + "p0/",
            absl::GetFlag(FLAGS_out_dir) + "p1/",
            absl::GetFlag(FLAGS_mod_length),
            absl::GetFlag(FLAGS_stat_param)
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
