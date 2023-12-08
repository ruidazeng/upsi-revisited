#ifndef PARTY_H_
#define PARTY_H_

#include "upsi/crypto/elgamal.h"
#include "upsi/crypto/threshold_paillier.h"
#include "upsi/util/elgamal_proto_util.h"
#include "upsi/util/proto_util.h"
#include "upsi/utils.h"

namespace upsi {

class Party { 
    protected:
        // used for various crypto operations
        Context* ctx_;
        ECGroup* group;

        // el gamal encryption tools
        std::unique_ptr<ElGamalEncrypter> encrypter;
        std::unique_ptr<ElGamalDecrypter> decrypter;

        // paillier encryption tool
        std::unique_ptr<ThresholdPaillier> paillier;

        // to keep track of time
        int total_days;
        int current_day = 0;

    public: 
        /**
         * instantiate a party
         *
         * epk_fn   : filename for el gamal (shared) public key
         * spk_fn   : filename for el gamal secret key
         * psk_fn   : filename for paillier key
         */
        Party(
            Context* ctx,
            std::string epk_fn,
            std::string esk_fn,
            std::string psk_fn,
            int total_days
        ) {
            this->ctx_ = ctx;

            this->total_days = total_days;

            // set up keys
            auto group = new ECGroup(ECGroup::Create(CURVE_ID, ctx).value());
            this->group = group; // TODO: delete

            auto epk = ProtoUtils::ReadProtoFromFile<ElGamalPublicKey>(epk_fn);
            if (!epk.ok()) {
                std::runtime_error("[Party] failure in reading shared public key");
            }

            encrypter = std::make_unique<ElGamalEncrypter>(
                this->group, elgamal_proto_util::DeserializePublicKey(this->group, epk.value()).value()
            );

            auto esk = ProtoUtils::ReadProtoFromFile<ElGamalSecretKey>(esk_fn);
            if (!esk.ok()) {
                std::runtime_error("[Party] failure in reading secret key");
            }

            decrypter = std::make_unique<ElGamalDecrypter>(
                elgamal_proto_util::DeserializePrivateKey(ctx_, esk.value()).value()
            );

            auto psk = ProtoUtils::ReadProtoFromFile<ThresholdPaillierKey>(psk_fn);
            if (!psk.ok()) {
                std::runtime_error("[Party] failure in reading paillier key");
            }

            paillier = std::make_unique<ThresholdPaillier>(ctx_, psk.value());
        }

        // protocol is finished when we've gone through all days
        bool protocol_finished() {
            std::cout << "[Party] " << this->current_day << " day out of " << this->total_days << " total days" << std::endl;
            return (this->current_day >= this->total_days);
        }
};

} // namespace upsi

#endif  // PARTY_H_
