#include "absl/flags/flag.h"
#include "absl/flags/parse.h"

#include "data_util.h"
#include "upsi/crypto/elgamal.h"
#include "upsi/crypto/threshold_paillier.h"
#include "upsi/util/elgamal_key_util.h"
#include "utils.h"

using namespace upsi;

ABSL_FLAG(bool, keys_only, false, "only generate keys");
ABSL_FLAG(bool, data_only, false, "only generate data");

ABSL_FLAG(std::string, dir, "data/", "name of directory for dataset files");
ABSL_FLAG(std::string, p0_fn, "party_zero", "prefix for party one's files");
ABSL_FLAG(std::string, p1_fn, "party_one", "prefix for party zero's files");
ABSL_FLAG(std::string, shared_fn, "shared", "prefix for shared key file");

ABSL_FLAG(int32_t, mod_length, 1536, "bit-length of Paillier modulus");
ABSL_FLAG(int32_t, stat_param, 100, "statistical parameter for Paillier");

ABSL_FLAG(int64_t, days, 10, "number of days the protocol is running for");
ABSL_FLAG(int64_t, p0_size, 50, "total elements in party one's set across all days");
ABSL_FLAG(int64_t, p1_size, 50, "total elements in party zero's set across all days");
ABSL_FLAG(int64_t, shared_size, 25, "total elements in intersection across all days");

ABSL_FLAG(int64_t, per_day, 0, "total elements in both sets each days");

ABSL_FLAG(int64_t, max_value, 1000, "maximum number for UPSI-SUM values");

Status GenerateJointData() {

    int64_t total = absl::GetFlag(FLAGS_days) * absl::GetFlag(FLAGS_per_day);

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


    // split into days
    auto i = 0;
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
                    absl::GetFlag(FLAGS_dir) + absl::GetFlag(FLAGS_p0_fn)
                    + "_" + std::to_string(day) + ".csv"
                )
            )
        );

        RETURN_IF_ERROR(
            WriteServerDatasetToFile(
                p1_elements,
                (
                    absl::GetFlag(FLAGS_dir) + absl::GetFlag(FLAGS_p1_fn)
                    + "_" + std::to_string(day) + ".csv"
                )
            )
        );
    }

    std::cout << "[Setup] mock data generated in " << absl::GetFlag(FLAGS_dir) << std::endl;
    std::cout << "        P0's total elements : " << total << std::endl;
    std::cout << "        P1's total elements : " << total << std::endl;
    std::cout << "        intersection size   : " << absl::GetFlag(FLAGS_shared_size) << std::endl;
    std::cout << "        intersection sum    : " << std::get<2>(datasets) << std::endl;

    return OkStatus();
}

StatusOr<int64_t> GenerateDailyData(
    int day, int64_t p0_size, int64_t p1_size, int64_t shared_size
) {
    ASSIGN_OR_RETURN(
        auto datasets,
        GenerateRandomDatabases(p1_size, p0_size, shared_size, absl::GetFlag(FLAGS_max_value))
    );

    RETURN_IF_ERROR(
        WriteClientDatasetToFile(
            std::get<1>(datasets).first,
            std::get<1>(datasets).second,
            (
                absl::GetFlag(FLAGS_dir) + absl::GetFlag(FLAGS_p0_fn)
                + "_" + std::to_string(day) + ".csv"
            )
        )
    );

    RETURN_IF_ERROR(
        WriteServerDatasetToFile(
            std::get<0>(datasets),
            (
                absl::GetFlag(FLAGS_dir) + absl::GetFlag(FLAGS_p1_fn)
                + "_" + std::to_string(day) + ".csv"
            )
        )
    );

    return std::get<2>(datasets);
}

Status GenerateData() {
    Context ctx;
    auto days = absl::GetFlag(FLAGS_days);

    // randomly choose how many elements are in each day
    std::vector<int64_t> p0_daily_sizes(days);
    std::vector<int64_t> p1_daily_sizes(days);

    for (int day = 0; day < days - 1; day++) {
        p0_daily_sizes[day] = ctx.GenerateRandLessThan(
            ctx.CreateBigNum(absl::GetFlag(FLAGS_p0_size))
        ).ToIntValue().value();

        p1_daily_sizes[day] = ctx.GenerateRandLessThan(
            ctx.CreateBigNum(absl::GetFlag(FLAGS_p1_size))
        ).ToIntValue().value();
    }

    // the last day should always be the total
    p0_daily_sizes[days - 1] = absl::GetFlag(FLAGS_p0_size);
    p1_daily_sizes[days - 1] = absl::GetFlag(FLAGS_p1_size);

    std::sort(p0_daily_sizes.begin(), p0_daily_sizes.end());
    std::sort(p1_daily_sizes.begin(), p1_daily_sizes.end());

    // generate each day's data
    int64_t p0_total = 0, p1_total = 0, overlap_total = 0, sum_total = 0;
    for (int day = 0; day < days; day++) {
        auto p0_today = p0_daily_sizes[day] - p0_total;
        auto p1_today = p1_daily_sizes[day] - p1_total;

        // choose a random intersection size each day
        int64_t overlap;
        if (std::min(p0_today, p1_today) == 0) {
            overlap = 0;
        } else {
            overlap = ctx.GenerateRandLessThan(
                ctx.CreateBigNum(std::min(p0_today, p1_today))
            ).ToIntValue().value();
        }

        ASSIGN_OR_RETURN(auto sum, GenerateDailyData(day + 1, p0_today, p1_today, overlap));

        p0_total += p0_today;
        p1_total += p1_today;
        overlap_total += overlap;
        sum_total += sum;
    }

    std::cout << "[Setup] mock data generated in " << absl::GetFlag(FLAGS_dir) << std::endl;
    std::cout << "        P0's total elements : " << p0_total << std::endl;
    std::cout << "        P1's total elements : " << p1_total << std::endl;
    std::cout << "        intersection size   : " << overlap_total << std::endl;
    std::cout << "        intersection sum    : " << sum_total << std::endl;
    return OkStatus();
}

Status GenerateKeys() {
    Context ctx;

    RETURN_IF_ERROR(
        elgamal_key_util::GenerateElGamalKeyPair(
            CURVE_ID,
            absl::GetFlag(FLAGS_p0_fn) + ".epub",
            absl::GetFlag(FLAGS_p0_fn) + ".ekey"
        )
    );

    RETURN_IF_ERROR(
        elgamal_key_util::GenerateElGamalKeyPair(
            CURVE_ID,
            absl::GetFlag(FLAGS_p1_fn) + ".epub",
            absl::GetFlag(FLAGS_p1_fn) + ".ekey"
        )
    );

    RETURN_IF_ERROR(
        elgamal_key_util::ComputeJointElGamalPublicKey(
            CURVE_ID,
            {
                absl::GetFlag(FLAGS_p0_fn) + ".epub",
                absl::GetFlag(FLAGS_p1_fn) + ".epub"
            },
            absl::GetFlag(FLAGS_shared_fn) + ".epub"
        )
    );

    RETURN_IF_ERROR(
        GenerateThresholdPaillierKeys(
            &ctx,
            absl::GetFlag(FLAGS_mod_length),
            absl::GetFlag(FLAGS_stat_param),
            absl::GetFlag(FLAGS_p0_fn) + ".pkey",
            absl::GetFlag(FLAGS_p1_fn) + ".pkey"
        )
    );

    std::cout << "[Setup] keys generated: ";
    std::cout << absl::GetFlag(FLAGS_p0_fn) << ".ekey, ";
    std::cout << absl::GetFlag(FLAGS_p1_fn) << ".ekey, ";
    std::cout << absl::GetFlag(FLAGS_shared_fn) << ".epub, ";
    std::cout << absl::GetFlag(FLAGS_p0_fn) << ".pkey, ";
    std::cout << absl::GetFlag(FLAGS_p1_fn) << ".pkey" << std::endl;
    return OkStatus();
}

int main(int argc, char** argv) {
    absl::ParseCommandLine(argc, argv);

    if (!absl::GetFlag(FLAGS_data_only)) {
        auto status = GenerateKeys();
        if (!status.ok()) {
            std::cerr << "[Setup] failure generating keys" << std::endl;
            std::cerr << status << std::endl;
            return 1;
        }
    }

    if (!absl::GetFlag(FLAGS_keys_only)) {
        Status status;
        if (absl::GetFlag(FLAGS_per_day) == 0) {
            status = GenerateData();
        } else {
            status = GenerateJointData();
        }
        if (!status.ok()) {
            std::cerr << "[Setup] failure generating datasets" << std::endl;
            std::cerr << status << std::endl;
            return 1;
        }
    }
    return 0;
}
