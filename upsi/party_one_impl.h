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
#include "upsi/crypto/elgamal.h"
#include "upsi/crypto/ec_commutative_cipher.h"
#include "upsi/crypto/paillier.h"
#include "upsi/crypto/threshold_paillier.h"
#include "upsi/crypto_tree.h"
#include "upsi/match.pb.h"
#include "upsi/message_sink.h"
#include "upsi/private_intersection.pb.h"
#include "upsi/upsi.pb.h"
#include "upsi/protocol_server.h"
#include "upsi/utils.h"
#include "upsi/util/status.inc"

namespace upsi {

// This class represents the "party 1" part of the updatable private set intersection protocol.
// This is the party that will NOT receive the output in one-sided UPSI.
class PartyOneImpl : public ProtocolServer {
    public:
        PartyOneImpl(
            Context* ctx,
            std::string pk_fn,
            std::string sk_fn,
            const std::vector<std::string>& elements,
            int32_t modulus_size,
            int32_t statistical_param,
            int total_days
        );

        ~PartyOneImpl() override = default;

        // Executes the next Server round and creates a response.
        Status Handle(
            const ClientMessage& request,
            MessageSink<ServerMessage>* server_message_sink
        ) override;

        bool protocol_finished() override { return protocol_finished_; }

    private:
        // Complete server side processing:
        // 1. Shuffle
        // 2. Mask with a random exponent
        // 3. Partial decryption (ElGamal/Paillier)
        // 4. Update P0's tree
        // 5. Update P1's tree
        // 6. Generate {Path_i}_i
        StatusOr<PartyOneMessage::ServerRoundOne> ServerProcessing(
            const PartyZeroMessage::ClientRoundOne& client_message,
            std::vector<std::string> server_elements
        );

        // Update elements and payloads
        std::vector<std::string> new_elements_;
        void UpdateElements(std::vector<std::string> new_elements);

        // Each party holds two crypto trees: one containing my elements, one containing the other party's elements.
        CryptoTree<UPSI_Element> my_crypto_tree;
        CryptoTree<Encrypted_UPSI_Element> other_crypto_tree;

        Context* ctx_;  // not owned
        ECGroup* group;

        std::vector<std::string> elements_;

        // el gamal encryption tools
        std::unique_ptr<ElGamalEncrypter> encrypter;
        std::unique_ptr<ElGamalDecrypter> decrypter;

        // current day and total days
        int current_day = 0;
        int total_days; // must be greater or equal to 1

        bool protocol_finished_ = false;
};

}  // namespace upsi

#endif  // PARTYONE_IMPL_H_
