#pragma once

#include "upsi/crypto/elgamal.h"
#include "upsi/crypto/threshold_paillier.h"
#include "upsi/params.h"
#include "upsi/roles.h"
#include "upsi/util/data_util.h"
#include "upsi/util/elgamal_proto_util.h"
#include "upsi/util/proto_util.h"
#include "upsi/util/status.inc"

namespace upsi {

namespace original {

class Party {
    protected:
        // used for various crypto operations
        Context* ctx_;
        ECGroup* group;

        // el gamal encryption tools
        std::unique_ptr<ElGamalEncrypter> their_pk;
        std::unique_ptr<ElGamalEncrypter> my_pk;
        std::unique_ptr<ElGamalDecrypter> decrypter;

        // one dataset for each day
        std::vector<std::vector<Element>> datasets;
    public:
        Party(PSIParams* params, const std::vector<Dataset>& datasets) : ctx_(params->ctx) {
            this->datasets.resize(params->total_days);
            for (int day = 0; day < params->total_days; day++) {
                this->datasets[day] = datasets[day].Elements();
            }

            this->group = new ECGroup(ECGroup::Create(CURVE_ID, ctx_).value());

            auto epk = ProtoUtils::ReadProtoFromFile<ElGamalPublicKey>(params->epk_fn);
            if (!epk.ok()) {
                std::runtime_error("[Party] failure in reading shared public key");
            }

            my_pk = std::make_unique<ElGamalEncrypter>(
                this->group,
                elgamal_proto_util::DeserializePublicKey(this->group, epk.value()).value()
            );

            epk = ProtoUtils::ReadProtoFromFile<ElGamalPublicKey>(params->ppk_fn);
            if (!epk.ok()) {
                std::runtime_error("[Party] failure in reading shared public key");
            }

            their_pk = std::make_unique<ElGamalEncrypter>(
                this->group,
                elgamal_proto_util::DeserializePublicKey(this->group, epk.value()).value()
            );

            auto esk = ProtoUtils::ReadProtoFromFile<ElGamalSecretKey>(params->esk_fn);
            if (!esk.ok()) {
                std::runtime_error("[Party] failure in reading secret key");
            }

            decrypter = std::make_unique<ElGamalDecrypter>(
                this->ctx_,
                elgamal_proto_util::DeserializePrivateKey(this->ctx_, esk.value()).value()
            );
        }

};

} // namespace original
} // namespace upsi
