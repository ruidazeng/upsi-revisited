#pragma once

#include "upsi/crypto_tree.h"
#include "upsi/roles.h"
#include "upsi/utils.h"
#include "upsi/crypto/context.h"
#include "upsi/crypto/ec_commutative_cipher.h"
#include "upsi/crypto/elgamal.h"
#include "upsi/crypto/paillier.h"
#include "upsi/crypto/threshold_paillier.h"
#include "upsi/deletion/party.h"
#include "upsi/network/message_sink.h"
#include "upsi/network/upsi.pb.h"
#include "upsi/util/data_util.h"
#include "upsi/util/status.inc"

namespace upsi {
namespace deletion {

class PartyOne : public Server, public Party {
    protected:
        volatile bool day_finished = false;

    public:
        PartyOne(
            PSIParams* params, const std::vector<Dataset>& datasets
        ) : Server(params), Party(params, emp::ALICE) {
            this->datasets.resize(params->total_days);
            for (int day = 0; day < params->total_days; day++) {
                this->datasets[day] = datasets[day].ElementsAndValues();
            }
        }

        ~PartyOne() = default;

        /**
         * update their tree, compute candidates, & send tree updates
         */
        StatusOr<PartyOneMessage::MessageII> GenerateMessageII(
            const PartyZeroMessage::MessageI& msg,
            std::vector<ElementAndPayload> elements
        );

        Status Handle(const ClientMessage& request, MessageSink<ServerMessage>* sink) override;

        void Reset() {
            day_finished = false;
        }

        void FinishDay() {
            day_finished = true;
        }

        bool ProtocolFinished() override {
            return day_finished;
        }
};


}  // namespace deletion
}  // namespace upsi
