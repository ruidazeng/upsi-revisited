#pragma once

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "upsi/roles.h"
#include "upsi/utils.h"
#include "upsi/crypto/context.h"
#include "upsi/crypto/ec_commutative_cipher.h"
#include "upsi/crypto/elgamal.h"
#include "upsi/crypto/threshold_paillier.h"
#include "upsi/crypto_tree.h"
#include "upsi/deletion-psi/party.h"
#include "upsi/network/connection.h"
#include "upsi/network/message_sink.h"
#include "upsi/network/upsi.pb.h"
#include "upsi/util/data_util.h"
#include "upsi/util/gc_util.h"
#include "upsi/util/status.inc"

namespace upsi {
namespace deletion {

class PartyZero : public Client, public Party {
    public:
        PartyZero(PSIParams* params) : Client(params), Party(params, emp::BOB) { }

        virtual ~PartyZero() = default;

        /**
         * set the datasets variable based on the functionality
         *
         * this can't happen in the constructor for weird inheritance reasons
         */
        void LoadData(const std::vector<Dataset>& datasets);

        Status Run(Connection* sink) override;

        /**
         * send tree updates & intersection candidates
         */
        Status SendMessageI(MessageSink<ClientMessage>* sink, std::vector<ElementAndPayload> elements);

        StatusOr<PartyZeroMessage::MessageI> GenerateMessageI(
            std::vector<ElementAndPayload> elements
        );

        /**
         * update their tree & send follow up message
         */
        Status ProcessMessageII(
            const PartyOneMessage::MessageII& res,
            MessageSink<ClientMessage>* sink
        );


        /**
         * delegate incoming messages to other methods
         */
        Status Handle(const ServerMessage& res, MessageSink<ClientMessage>* sink) override;

        void PrintResult() override;
        
        Status SecondPhase();

    protected:
    
    	std::set<std::string> intersection;
        uint64_t result = 0;
};

}  // namespace deletion
}  // namespace upsi
