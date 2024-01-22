#include "absl/status/status.h"
#include "upsi/crypto/context.h"
#include "upsi/crypto/ec_group.h"
#include "upsi/util/data_util.h"
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

// create El Gamal public and private keys
Status GenerateElGamalKeys(
    Context* ctx,
    std::string p0_dir,
    std::string p1_dir
);

// create plaintext and encrypted trees with the given data
Status GenerateTrees(
    Context* ctx,
    ECGroup* group,
    std::vector<Element> data,
    const std::string& key_dir,
    const std::string& plaintext_dir,
    const std::string& encrypted_dir,
    std::string pk_fn = "shared.pub"
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

Status GenerateTrees(
    Context* ctx,
    ECGroup* group,
    const Dataset& data,
    const std::string& key_dir,
    const std::string& plaintext_dir,
    const std::string& encrypted_dir
);

}
