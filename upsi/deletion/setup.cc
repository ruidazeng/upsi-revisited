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

ABSL_FLAG(uint32_t, daily_size, 64, "total elements in each set on each day");
ABSL_FLAG(uint32_t, start_size, 0, "size of the initial trees");
ABSL_FLAG(int32_t, shared_size, -1, "total elements in intersection across all days");

ABSL_FLAG(int32_t, max_value, 100, "maximum number for UPSI-SUM values");

ABSL_FLAG(bool, expected, true, "compute expected cardinality and sum");


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
        auto status = GenerateDeletionData(
            &ctx,
            absl::GetFlag(FLAGS_out_dir) + "p0/",
            absl::GetFlag(FLAGS_out_dir) + "p1/",
            absl::GetFlag(FLAGS_data_dir) + "p0/",
            absl::GetFlag(FLAGS_data_dir) + "p1/",
            absl::GetFlag(FLAGS_days),
            absl::GetFlag(FLAGS_start_size),
            absl::GetFlag(FLAGS_daily_size),
            absl::GetFlag(FLAGS_shared_size),
            absl::GetFlag(FLAGS_max_value),
            absl::GetFlag(FLAGS_expected)
        );
        if (!status.ok()) {
            std::cerr << "[Setup] failure generating datasets" << std::endl;
            std::cerr << status << std::endl;
            return 1;
        }
    }
    return 0;
}
