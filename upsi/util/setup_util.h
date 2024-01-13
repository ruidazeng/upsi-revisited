#include "absl/status/status.h"
#include "upsi/crypto/context.h"
#include "upsi/crypto/ec_group.h"
#include "upsi/util/status.inc"
#include "upsi/utils.h"

namespace upsi {

// create threshold El Gamal and Paillier public and private keys
Status GenerateThresholdKeys(
    Context* ctx,
    std::string p0_dir,
    std::string p1_dir,
    int32_t mod_length,
    int32_t stat_param
);

// create Paillier public and private keys
Status GeneratePaillierKeys(
    Context* ctx,
    std::string p0_dir,
    std::string p1_dir,
    int32_t mod_length,
    int32_t stat_param
);

// create mock daily data
Status GenerateAdditionData(
    Context* ctx,
    std::string p0_key_dir, // where to find the encryption keys
    std::string p1_key_dir,
    std::string p0_dir,     // where to put the data
    std::string p1_dir,
    uint32_t days,          // how many days to generate daily data for
    uint32_t start_size,    // number of elements in the trees saved to disk
    uint32_t daily_size,    // number of elements in each day's data
    int32_t shared_size,    // number of elements in intersection (including trees)
    int32_t max_value,      // maximum size of sum values
    Functionality func,     // which functionality to generate data for
    bool expected = true    // calculate expected cardinality and sum
);

Status GenerateDeletionData(
    Context* ctx,
    std::string p0_key_dir, // where to find the encryption keys
    std::string p1_key_dir,
    std::string p0_dir,     // where to put the data
    std::string p1_dir,
    uint32_t days,          // how many days to generate daily data for
    uint32_t start_size,    // number of elements in the trees saved to disk
    uint32_t daily_size,    // number of elements in each day's data
    int32_t shared_size,    // number of elements in intersection (including trees)
    int32_t max_value,      // maximum size of sum values
    bool expected = true    // calculate expected cardinality and sum
);

// create plaintext and encrypted trees with the given data
Status GenerateTrees(
    Context* ctx,
    ECGroup* group,
    std::vector<Element> data,
    const std::string& key_dir,
    const std::string& plaintext_dir,
    const std::string& encrypted_dir
);

Status GenerateTrees(
    Context* ctx,
    ECGroup* group,
    std::vector<ElementAndPayload> data,
    const std::string& key_dir,
    const std::string& plaintext_dir,
    const std::string& encrypted_dir,
    Functionality func
);

}
