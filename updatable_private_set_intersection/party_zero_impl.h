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

#ifndef UPDATABLE_PRIVATE_SET_INTERSECTION_PRIVATE_INTERSECTION_PARTYZERO_IMPL_H_
#define UPDATABLE_PRIVATE_SET_INTERSECTION_PRIVATE_INTERSECTION_PARTYZERO_IMPL_H_

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
#include "updatable_private_set_intersection/protocol_client.h"
#include "updatable_private_set_intersection/utils.h"
#include "updatable_private_set_intersection/util/status.inc"

namespace updatable_private_set_intersection {

// This class represents the "party 0" part of the updatable private set intersection protocol.
// This is the party that will receive the output in one-sided UPSI.

class PrivateIntersectionProtocolPartyZeroImpl : public ProtocolClient {
 public:
    PrivateIntersectionProtocolPartyZeroImpl(
      Context* ctx, const std::vector<std::string>& elements,
      const std::vector<BigNum>& payloads, int32_t modulus_size, int32_t statistical_param,
      int total_days);

    ~PrivateIntersectionProtocolPartyZeroImpl() override = default;

    // Generates the StartProtocol message and sends it on the message sink.
    // This function also contains the first step of Threshold ElGamal key exchange.
    // Sends the Threshold ElGamal public key pairs (g, y) to the server.
    Status StartProtocol(MessageSink<ClientMessage>* client_message_sink) override;

    // Initiate ClientPreprocessing. Every new day, call this function so
    // P_0 will send ClientRoundOne to server.
    Status ClientSendRoundOne(MessageSink<ClientMessage>* client_message_sink);

    // Executes the next Client round and creates a new server request, which must
    // be sent to the server unless the protocol is finished.
    //
    // If the ServerMessage is ServerKeyExchange, nothing will be sent on the message
    // sink. But P_0 will call ClientExchange to complete the key exchange process.
    //
    // If the ServerMessage is ServerRoundOne, again nothing will be sent on
    // the message sink, and the client will call ClientPostProcessing to complete
    // the day worth of UPSI.
    //
    // Fails with InvalidArgument if the message is not a
    // PrivateIntersectionServerMessage of the expected round, or if the
    // message is otherwise not as expected. Forwards all other failures
    // encountered.
    Status Handle(const ServerMessage& server_message,
                  MessageSink<ClientMessage>* client_message_sink) override;


    bool protocol_finished() override { return protocol_finished_; }

 private:
    // Complete P_0 key exchange:
    // 1. Retrieve P_1's (g, y)
    // 2. Generate Threshold ElGamal public key from shares, save it to P_0's member variable
    Status ClientExchange(const PrivateIntersectionClientMessage::ServerKeyExchange&
                           server_message);
   
    // Start client side processing (for a new day of UPSI)
    // 1. Insert into my own tree
    // 2. Generate {Path_i}_i
    // 3. ElGamal Encryptor for elements, Threshold Paillier Encryptor for payloads 
    // 4. Generate Client Round One message (Party 0) to send to Party 1
    StatusOr<PrivateIntersectionClientMessage::ClientRoundOne>
    ClientPreProcessing(std::vector<std::string> elements);

    // Complete client side processing (for the same day of UPSI)
    // 1. Partial decryption (ElGamal/Paillier)
    // 2. Update P0's tree
    // 3. Update P1's tree
    // 4. Payload Processing
    // TODO: PRINT RESULTS???
    Status ClientPostProcessing(const PrivateIntersectionClientMessage::ServerRoundOne&
                           server_message);

    // Update elements and payloads
    std::vector<std::string> new_elements_;
    std::vector<BigNum> new_payloads_;
    void UpdateElements(std::vector<std::string> new_elements);
    void UpdatePayloads(std::vector<BigNum> new_payloads);
    
    // Each party holds two crypto trees: one containing my elements, one containing the other party's elements.
    CryptoTree<UPSI_Element> my_crypto_tree;
    CryptoTree<Encrypted_UPSI_Element> other_crypto_tree;

    Context* ctx_;  // not owned
    ECGroup ec_group;
    
    std::vector<std::string> elements_;
    std::vector<BigNum> payloads_;

    // The ElGamal key pairs
    elgamal::PublicKey elgamal_public_key; // (g, y)
    elgamal::PrivateKey elgamal_private_key; // x

    // The ElGamal shared public key (2-out-of-2 threshold ElGamal encryption scheme)
    elgamal::PublicKey shared_elgamal_public_key; // shared (g, x)

    // The Threshold Paillier object
    // ThresholdPaillier threshold_paillier;

    // current day and total days
    int current_day = 0;
    int total_days; // must be greater or equal to 1

    bool protocol_finished_ = false;
};

}  // namespace updatable_private_set_intersection

#endif  // UPDATABLE_PRIVATE_SET_INTERSECTION_PRIVATE_INTERSECTION_PARTYZERO_IMPL_H_
