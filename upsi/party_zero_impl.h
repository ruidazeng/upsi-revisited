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

#ifndef PARTYZERO_IMPL_H_
#define PARTYZERO_IMPL_H_

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "upsi/crypto/context.h"
#include "upsi/crypto/ec_commutative_cipher.h"
#include "upsi/crypto/elgamal.h"
#include "upsi/crypto/paillier.h"
#include "upsi/crypto/threshold_paillier.h"
#include "upsi/crypto_tree.h"
#include "upsi/data_util.h"
#include "upsi/match.pb.h"
#include "upsi/message_sink.h"
#include "upsi/private_intersection.pb.h"
#include "upsi/protocol_client.h"
#include "upsi/upsi.pb.h"
#include "upsi/util/status.inc"
#include "upsi/utils.h"

namespace upsi {

// This class represents the "party 0" part of the updatable private set intersection protocol.
// This is the party that will receive the output in one-sided UPSI.

class PartyZeroImpl : public ProtocolClient {
    public:
        PartyZeroImpl(
            Context* ctx,
            std::string pk_fn,
            std::string sk_fn,
            const std::vector<PartyZeroDataset>& elements,
            int32_t modulus_size,
            int32_t statistical_param,
            int total_days
        );

        ~PartyZeroImpl() override = default;

        /**
         * send the first message of the day
         */
        Status SendMessageI(MessageSink<ClientMessage>* sink);

        // Executes the next Client round and creates a new server request, which must
        // be sent to the server unless the protocol is finished.
        //
        // If the ServerMessage is MessageII, again nothing will be sent on
        // the message sink, and the client will call ClientPostProcessing to complete
        // the day worth of UPSI.
        //
        // Fails with InvalidArgument if the message is not a
        // PartyOneMessage of the expected round, or if the
        // message is otherwise not as expected. Forwards all other failures
        // encountered.
        Status Handle(const ServerMessage& response, MessageSink<ClientMessage>* sink) override;

        bool protocol_finished() override { return protocol_finished_; }

        int64_t cardinality = 0;

    private:
        // Start client side processing (for a new day of UPSI)
        // 1. Insert into my own tree
        // 2. Generate {Path_i}_i
        // 3. ElGamal Encryptor for elements, Threshold Paillier Encryptor for payloads
        // 4. Generate Client Round One message (Party 0) to send to Party 1
        StatusOr<PartyZeroMessage::MessageI> GenerateMessageI(
            std::vector<std::string> elements
        );

        // Complete client side processing (for the same day of UPSI)
        // 1. Partial decryption (ElGamal/Paillier)
        // 2. Update P0's tree
        // 3. Update P1's tree
        // 4. Payload Processing
        // TODO: PRINT RESULTS???
        Status ClientPostProcessing(const PartyOneMessage::MessageII& server_message);

        // Each party holds two crypto trees: one containing my elements, one containing the other party's elements.
        CryptoTree<UPSI_Element> my_tree;
        CryptoTree<Encrypted_UPSI_Element> other_tree;

        Context* ctx_;  // not owned
        ECGroup* group;

        std::vector<PartyZeroDataset> elements_;

        // el gamal encryption tools
        std::unique_ptr<ElGamalEncrypter> encrypter;
        std::unique_ptr<ElGamalDecrypter> decrypter;

        // current day and total days
        int current_day = 0;
        int total_days; // must be greater or equal to 1

        bool protocol_finished_ = false;
};

}  // namespace upsi

#endif  // PARTYZERO_IMPL_H_
