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

#ifndef UPDATABLE_PRIVATE_SET_INTERSECTION_PRIVATE_INTERSECTION_PARTYONE_IMPL_H_
#define UPDATABLE_PRIVATE_SET_INTERSECTION_PRIVATE_INTERSECTION_PARTYONE_IMPL_H_

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
    PartyOneImpl (
      Context* ctx, const std::vector<std::string>& elements,
      int32_t modulus_size, int32_t statistical_param, int total_days);

    ~PartyOneImpl() override = default;

    // Executes the next Server round and creates a response.
    Status Handle(const ClientMessage& request,
                  MessageSink<ServerMessage>* server_message_sink) override;

    bool protocol_finished() override { return protocol_finished_; }

 private:
    // Complete P_1 key exchange:
    // 1. Retrieve P_0's (g, y)
    // 2. Generate Threshold ElGamal public key from shares, save it to P_1's member variable
    // 3. Generate ServerKeyExchange message using P_1's (g, y)
    StatusOr<PrivateIntersectionServerMessage::ServerExchange>
    ServerExchange(const PrivateIntersectionClientMessage::StartProtocolRequest&
                           client_message);

    // Complete server side processing:
    // 1. Shuffle
    // 2. Mask with a random exponent
    // 3. Partial decryption (ElGamal/Paillier)
    // 4. Update P0's tree
    // 5. Update P1's tree
    // 6. Generate {Path_i}_i
    StatusOr<PrivateIntersectionServerMessage::ServerRoundOne>
    ServerProcessing(const PrivateIntersectionClientMessage::ClientRoundOne&
                           client_message, std::vector<std::string> server_elements);

    // Update elements and payloads
    std::vector<std::string> new_elements_;
    void UpdateElements(std::vector<std::string> new_elements);

    // Each party holds two crypto trees: one containing my elements, one containing the other party's elements.
    CryptoTree<UPSI_Element> my_crypto_tree;
    CryptoTree<Encrypted_UPSI_Element> other_crypto_tree;
    
    Context* ctx_;  // not owned
    ECGroup* ec_group;
    
    std::vector<std::string> elements_;
    
    // The ElGamal key pairs
    std::unique_ptr<elgamal::PublicKey> elgamal_public_key; // (g, y)
    std::unique_ptr<elgamal::PrivateKey> elgamal_private_key; // x
    

    // The ElGamal shared public key (2-out-of-2 threshold ElGamal encryption scheme)
    std::unique_ptr<elgamal::PublicKey> shared_elgamal_public_key; // shared (g, x)

    // The Threshold Paillier object
    // ThresholdPaillier threshold_paillier;
   
    // current day and total days
    int current_day = 0;
    int total_days; // must be greater or equal to 1

    bool protocol_finished_ = false;

};

}  // namespace upsi

#endif  // UPDATABLE_PRIVATE_SET_INTERSECTION_PRIVATE_INTERSECTION_PARTYONE_IMPL_H_
