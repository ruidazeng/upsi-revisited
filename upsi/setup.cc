#include "absl/flags/flag.h"
#include "absl/flags/parse.h"

#include "upsi/crypto/elgamal.h"
#include "upsi/util/elgamal_key_util.h"
#include "utils.h"

using namespace upsi;

ABSL_FLAG(
    std::string, party_one_fn, "party_one", "prefix for party one's key files"
);

ABSL_FLAG(
    std::string, party_zero_fn, "party_zero", "prefix for party zero's key files"
);

ABSL_FLAG(
    std::string, shared_fn, "shared", "prefix for shared key file"
);

Status GenerateKeys() {
    RETURN_IF_ERROR(
        elgamal_key_util::GenerateElGamalKeyPair(
            CURVE_ID,
            absl::GetFlag(FLAGS_party_zero_fn) + ".pub",
            absl::GetFlag(FLAGS_party_zero_fn) + ".key"
        )
    );

    RETURN_IF_ERROR(
        elgamal_key_util::GenerateElGamalKeyPair(
            CURVE_ID,
            absl::GetFlag(FLAGS_party_one_fn) + ".pub",
            absl::GetFlag(FLAGS_party_one_fn) + ".key"
        )
    );

    RETURN_IF_ERROR(
        elgamal_key_util::ComputeJointElGamalPublicKey(
            CURVE_ID,
            {
                absl::GetFlag(FLAGS_party_one_fn) + ".pub",
                absl::GetFlag(FLAGS_party_one_fn) + ".pub"
            },
            absl::GetFlag(FLAGS_shared_fn) + ".pub"
        )
    );

    return OkStatus();
}

int main(int argc, char** argv) {
    absl::ParseCommandLine(argc, argv);

    auto status = GenerateKeys();
    if (!status.ok()) {
        std::cerr << "[Setup] failure generating keys" << std::endl;
        std::cerr << status << std::endl;
    }
}
