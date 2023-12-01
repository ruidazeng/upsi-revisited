#include "absl/flags/flag.h"
#include "absl/flags/parse.h"

#include "upsi/crypto/elgamal.h"
#include "upsi/util/elgamal_key_util.h"
#include "utils.h"
#include "data_util.h"

using namespace upsi;

ABSL_FLAG(std::string, dir, "data/", "name of directory for dataset files");
ABSL_FLAG(std::string, p0_fn, "party_zero", "prefix for party one's files");
ABSL_FLAG(std::string, p1_fn, "party_one", "prefix for party zero's files");
ABSL_FLAG(std::string, shared_fn, "shared", "prefix for shared key file");
ABSL_FLAG(int64_t, days, 1, "number of days the protocol is running for");
ABSL_FLAG(int64_t, p0_size, 10, "total elements in party one's set across all days");
ABSL_FLAG(int64_t, p1_size, 10, "total elements in party zero's set across all days");
ABSL_FLAG(int64_t, shared_size, 10, "total elements in intersection across all days");
ABSL_FLAG(int64_t, max_value, 1000, "maximum number for UPSI-SUM values");

Status GenerateDailyData(int day, int64_t p0_size, int64_t p1_size, int64_t shared_size) {
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
    return OkStatus();
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
    int64_t p0_total = 0, p1_total = 0, overlap_total = 0;
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

        RETURN_IF_ERROR(GenerateDailyData(day + 1, p0_today, p1_today, overlap));

        p0_total += p0_today;
        p1_total += p1_today;
        overlap_total += overlap;
    }

    std::cout << "[Setup] mock data generated in " << absl::GetFlag(FLAGS_dir) << std::endl;
    std::cout << "        P0's total elements   : " << p0_total << std::endl;
    std::cout << "        P1's total elements   : " << p1_total << std::endl;
    std::cout << "        shared total elements : " << overlap_total << std::endl;
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
                absl::GetFlag(FLAGS_p0_fn) + ".pub",
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
