#include "absl/flags/flag.h"
#include "absl/flags/parse.h"

#include "upsi/crypto/elgamal.h"
#include "upsi/util/elgamal_key_util.h"
#include "utils.h"
#include "data_util.h"

using namespace upsi;

ABSL_FLAG(std::string, p0_fn, "party_zero", "prefix for party one's files");
ABSL_FLAG(std::string, p1_fn, "party_one", "prefix for party zero's files");
ABSL_FLAG(std::string, shared_fn, "shared", "prefix for shared key file");
ABSL_FLAG(int64_t, p0_size, 250, "total elements in party one's set across all days");
ABSL_FLAG(int64_t, p1_size, 250, "total elements in party zero's set across all days");
ABSL_FLAG(int64_t, shared_size, 100, "total elements in intersection across all days");
ABSL_FLAG(int64_t, max_value, 1000, "maximum number for UPSI-SUM values");

Status GenerateData() {
    ASSIGN_OR_RETURN(
        auto datasets,
        GenerateRandomDatabases(
            absl::GetFlag(FLAGS_p1_size),
            absl::GetFlag(FLAGS_p0_size),
            absl::GetFlag(FLAGS_shared_size),
            absl::GetFlag(FLAGS_max_value)
        )
    );

    RETURN_IF_ERROR(
        WriteClientDatasetToFile(
            std::get<1>(datasets).first,
            std::get<1>(datasets).second,
            absl::GetFlag(FLAGS_p0_fn) + ".csv"
        )
    );

    RETURN_IF_ERROR(
        WriteServerDatasetToFile(
            std::get<0>(datasets),
            absl::GetFlag(FLAGS_p1_fn) + ".csv"
        )
    );

    std::cout << "[Setup] mock data generated: ";
    std::cout << absl::GetFlag(FLAGS_p0_fn) << ".csv, ";
    std::cout << absl::GetFlag(FLAGS_p1_fn) << ".csv" << std::endl;
    return OkStatus();
}

Status GenerateKeys() {
    RETURN_IF_ERROR(
        elgamal_key_util::GenerateElGamalKeyPair(
            CURVE_ID,
            absl::GetFlag(FLAGS_p0_fn) + ".pub",
            absl::GetFlag(FLAGS_p0_fn) + ".key"
        )
    );

    RETURN_IF_ERROR(
        elgamal_key_util::GenerateElGamalKeyPair(
            CURVE_ID,
            absl::GetFlag(FLAGS_p1_fn) + ".pub",
            absl::GetFlag(FLAGS_p1_fn) + ".key"
        )
    );

    RETURN_IF_ERROR(
        elgamal_key_util::ComputeJointElGamalPublicKey(
            CURVE_ID,
            {
                absl::GetFlag(FLAGS_p1_fn) + ".pub",
                absl::GetFlag(FLAGS_p1_fn) + ".pub"
            },
            absl::GetFlag(FLAGS_shared_fn) + ".pub"
        )
    );

    std::cout << "[Setup] keys generated: ";
    std::cout << absl::GetFlag(FLAGS_p0_fn) << ".key, ";
    std::cout << absl::GetFlag(FLAGS_p1_fn) << ".key, ";
    std::cout << absl::GetFlag(FLAGS_shared_fn) << ".pub" << std::endl;
    return OkStatus();
}

int main(int argc, char** argv) {
    absl::ParseCommandLine(argc, argv);

    auto status = GenerateKeys();
    if (!status.ok()) {
        std::cerr << "[Setup] failure generating keys" << std::endl;
        std::cerr << status << std::endl;
    }

    status = GenerateData();
    if (!status.ok()) {
        std::cerr << "[Setup] failure generating datasets" << std::endl;
        std::cerr << status << std::endl;
    }
}
