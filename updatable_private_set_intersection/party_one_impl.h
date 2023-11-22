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

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "updatable_private_set_intersection/crypto/context.h"
#include "updatable_private_set_intersection/crypto/elgamal.h"
#include "updatable_private_set_intersection/crypto/ec_commutative_cipher.h"
#include "updatable_private_set_intersection/crypto/paillier.h"
#include "updatable_private_set_intersection/crypto/threshold_paillier.h"
#include "updatable_private_set_intersection/crypto_tree.h"
#include "updatable_private_set_intersection/match.pb.h"
#include "updatable_private_set_intersection/message_sink.h"
#include "updatable_private_set_intersection/private_intersection.pb.h"
#include "updatable_private_set_intersection/updatable_private_set_intersection.pb.h"
#include "updatable_private_set_intersection/protocol_server.h"
#include "updatable_private_set_intersection/utils.h"
#include "updatable_private_set_intersection/util/status.inc"

namespace updatable_private_set_intersection {

// This class represents the "party 1" part of the updatable private set intersection protocol.
// This is the party that will NOT receive the output in one-sided UPSI.
class PrivateIntersectionProtocolPartyOneImpl : public ProtocolServer {
 public:
    PrivateIntersectionProtocolPartyOneImpl (
      Context* ctx, const std::vector<std::string>& elements,
      int32_t modulus_size, int32_t statistical_param);

    ~PrivateIntersectionProtocolPartyOneImpl() override = default;

    // Executes the next Server round and creates a response.
    Status Handle(const ClientMessage& request,
                  MessageSink<ServerMessage>* server_message_sink) override

    bool protocol_finished() override { return protocol_finished_; }

 private:
    // Complete P_1 key exchange:
    // 1. Retrieve P_0's (g, y)
    // 2. Generate Threshold ElGamal public key from shares, save it to P_1's member variable
    // 3. Generate ServerKeyExchange message using P_1's (g, y)
    StatusOr<PrivateIntersectionServerMessage::ServerKeyExchange>
    ServerKeyExchange(const PrivateIntersectionClientMessage::StartProtocolRequest&
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
                           client_message);

    // Update elements and payloads
    std::vector<std::string> new_elements_;
    void UpdateElements(std::vector<std::string> new_elements);

    // Each party holds two crypto trees: one containing my elements, one containing the other party's elements.
    CryptoTree<UPSI_Element> my_crypto_tree;
    CryptoTree<Encrypted_UPSI_Element> other_crypto_tree;
    
    Context* ctx_;  // not owned
    std::vector<std::string> elements_;
    
    // The ElGamal key pairs
    elgamal::PublicKey elgamal_public_key; // (g, y)
    elgamal::PrivateKey elgamal_private_key; // x

    // The ElGamal shared public key (2-out-of-2 threshold ElGamal encryption scheme)
    elgamal::PublicKey shared_elgamal_public_key; // shared (g, x)
    
    // The Threshold Paillier object
    // ThresholdPaillier threshold_paillier;


};

}  // namespace updatable_private_set_intersection

#endif  // UPDATABLE_PRIVATE_SET_INTERSECTION_PRIVATE_INTERSECTION_PARTYONE_IMPL_H_
