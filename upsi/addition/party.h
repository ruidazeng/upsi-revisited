#pragma once

#include "upsi/crypto/elgamal.h"
#include "upsi/crypto/threshold_paillier.h"
#include "upsi/params.h"
#include "upsi/roles.h"
#include "upsi/util/elgamal_proto_util.h"
#include "upsi/util/proto_util.h"
#include "upsi/util/status.inc"

namespace upsi {

namespace addonly {

template<typename P, typename E>
class Party : public HasTree<P, E> {
    protected:
        // el gamal encryption tools
        std::unique_ptr<ElGamalEncrypter> encrypter;
        std::unique_ptr<ElGamalDecrypter> decrypter;

        // paillier encryption tool
        std::unique_ptr<ThresholdPaillier> paillier;
    public:
        Party(PSIParams* params) : HasTree<P, E>(params) {
            auto epk = ProtoUtils::ReadProtoFromFile<ElGamalPublicKey>(params->epk_fn);
            if (!epk.ok()) {
                std::runtime_error("[Party] failure in reading shared public key");
            }

            encrypter = std::make_unique<ElGamalEncrypter>(
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

            // set up pailier key
            auto psk = ProtoUtils::ReadProtoFromFile<ThresholdPaillierKey>(params->psk_fn);
            if (!psk.ok()) {
                std::runtime_error("[Party] failure in reading paillier key");
            }

            paillier = std::make_unique<ThresholdPaillier>(this->ctx_, psk.value());
        }

};

} // namespace addonly
} // namespace upsi
