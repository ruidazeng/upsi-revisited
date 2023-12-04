/*
 * Copyright 2019 Google LLC.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef PARTYONE_IMPL_H_
#define PARTYONE_IMPL_H_

#include "upsi/crypto/context.h"
#include "upsi/crypto/ec_commutative_cipher.h"
#include "upsi/crypto/elgamal.h"
#include "upsi/crypto/paillier.h"
#include "upsi/crypto/threshold_paillier.h"
#include "upsi/crypto_tree.h"
#include "upsi/data_util.h"
#include "upsi/match.pb.h"
#include "upsi/message_sink.h"
#include "upsi/party_impl.h"
#include "upsi/private_intersection.pb.h"
#include "upsi/protocol_server.h"
#include "upsi/upsi.pb.h"
#include "upsi/util/status.inc"
#include "upsi/utils.h"

namespace upsi {

// This class represents the "party 1" part of the updatable private set intersection protocol.
// This is the party that will NOT receive the output in one-sided UPSI.
class PartyOneImpl : public ProtocolServer, public PartyImpl<PartyOneDataset> {
    public:
        
        // use the default constructor
        using PartyImpl::PartyImpl;

        ~PartyOneImpl() override = default;

        /**
         * update their tree, compute candidates, & send tree updates
         */
        StatusOr<PartyOneMessage::MessageII> GenerateMessageII(
            const PartyZeroMessage::MessageI& msg,
            std::vector<Element> elements
        );

        /**
         * respond to any follow up messages
         */
        StatusOr<PartyOneMessage::MessageIV> GenerateMessageIV(
            const PartyZeroMessage::MessageIII& msg
        );

        /**
         * delegate incoming messages to other methods
         */
        Status Handle(
            const ClientMessage& request,
            MessageSink<ServerMessage>* server_message_sink
        ) override;

        /**
         * protocol is finished when we've gone through all days
         */
        bool protocol_finished() override { 
            return (this->current_day == this->total_days);
        }

    private:
        // our plaintext tree & their encrypted tree
        CryptoTree<Element> my_tree;
        CryptoTree<CiphertextAndPayload> other_tree;
};

}  // namespace upsi

#endif  // PARTYONE_IMPL_H_
