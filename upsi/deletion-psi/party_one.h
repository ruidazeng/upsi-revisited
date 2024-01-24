#pragma once

#include "upsi/crypto_tree.h"
#include "upsi/roles.h"
#include "upsi/utils.h"
#include "upsi/crypto/context.h"
#include "upsi/crypto/ec_commutative_cipher.h"
#include "upsi/crypto/elgamal.h"
#include "upsi/crypto/paillier.h"
#include "upsi/crypto/threshold_paillier.h"
#include "upsi/deletion-psi/party.h"
#include "upsi/network/message_sink.h"
#include "upsi/network/upsi.pb.h"
#include "upsi/util/data_util.h"
#include "upsi/util/status.inc"

namespace upsi {
namespace deletion_psi {

class PartyOne : public Server, public Party {
    protected:
        volatile bool day_finished = false;
        volatile bool first_round_finished = false;

    public:
        PartyOne(
            PSIParams* params, const std::vector<Dataset>& datasets
        ) : Server(params), Party(params, emp::ALICE) {
            this->datasets[0].resize(params->total_days);
            this->datasets[1].resize(params->total_days);
            for (int day = 0; day < params->total_days; day++) {
		        std::vector<std::pair<BigNum, BigNum>> cur_day = datasets[day].ElementsAndValues();
				int cnt = cur_day.size();
					for (int i = 0; i < cnt; ++i) {
						if(cur_day[i].second.IsNonNegative()) this->datasets[1][day].push_back(cur_day[i]); //addition
						else this->datasets[0][day].push_back(cur_day[i]); //deletion
					}
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
            first_round_finished = false;
        }

        void FinishDay() {
            if(first_round_finished) {day_finished = true; current_day++;}
            else first_round_finished = true;
        }

        bool ProtocolFinished() override {
            return day_finished;
        }
        
        Status SecondPhase();
};


}  // namespace deletion_psi
}  // namespace upsi
