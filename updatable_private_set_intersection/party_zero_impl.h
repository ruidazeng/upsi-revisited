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

#ifndef updatable_private_set_intersection_PRIVATE_INTERSECTION_SUM_PARTY_ZERO_IMPL_H_
#define updatable_private_set_intersection_PRIVATE_INTERSECTION_SUM_PARTY_ZERO_IMPL_H_

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "updatable_private_set_intersection/crypto/context.h"
#include "updatable_private_set_intersection/crypto/elgamal.h"
#include "updatable_private_set_intersection/crypto/ec_commutative_cipher.h"
#include "updatable_private_set_intersection/crypto/paillier.h"
#include "updatable_private_set_intersection/crypto_tree.h"
#include "updatable_private_set_intersection/match.pb.h"
#include "updatable_private_set_intersection/message_sink.h"
#include "updatable_private_set_intersection/private_intersection_sum.pb.h"
#include "updatable_private_set_intersection/updatable_private_set_intersection.pb.h"
#include "updatable_private_set_intersection/protocol_client.h"
#include "updatable_private_set_intersection/utils.h"
#include "updatable_private_set_intersection/util/status.inc"

namespace updatable_private_set_intersection {

// This class represents the "party 0" part of the updatable private set intersection protocol.
// This is the party that will receive the output in one-sided UPSI.

class PrivateIntersectionSumProtocolPartyZeroImpl : public ProtocolClient {
 public:
  PrivateIntersectionSumProtocolPartyZeroImpl(Context* ctx, int32_t modulus_size);

  // Generates the StartProtocol message and sends it on the message sink.
  Status StartProtocol(
      MessageSink<ClientMessage>* client_message_sink) override;

  // Executes the next Client round and creates a new server request, which must
  // be sent to the server unless the protocol is finished.
  //
  // If the ServerMessage is ServerRoundOne, a ClientRoundOne will be sent on
  // the message sink, containing the encrypted client identifiers and
  // associated values, and the re-encrypted and shuffled server identifiers.
  //
  // If the ServerMessage is ServerRoundTwo, nothing will be sent on
  // the message sink, and the client will internally store the intersection sum
  // and size. The intersection sum and size can be retrieved either through
  // accessors, or by calling PrintOutput.
  //
  // Fails with InvalidArgument if the message is not a
  // PrivateIntersectionSumServerMessage of the expected round, or if the
  // message is otherwise not as expected. Forwards all other failures
  // encountered.
  Status Handle(const ServerMessage& server_message,
                MessageSink<ClientMessage>* client_message_sink) override;


  bool protocol_finished() override { return protocol_finished_; }

 private:
  // Each party holds two crypto trees: one containing my elements, one containing the other party's elements.
  CryptoTree<UPSI_Element> my_crypto_tree;
  CryptoTree<Encrypted_UPSI_Element> other_crypto_tree;

  // The server sends the first message of the protocol, which contains its
  // encrypted set.  This party then re-encrypts that set and replies with the
  // reencrypted values and its own encrypted set.
//   StatusOr<PrivateIntersectionSumClientMessage::ClientRoundOne> ReEncryptSet(
//       const PrivateIntersectionSumServerMessage::ServerRoundOne&
//           server_message);

  // After the server computes the intersection-sum, it will send it back to
  // this party for decryption, together with the intersection_size. This party
  // will decrypt and output the intersection sum and intersection size.
//   StatusOr<std::pair<int64_t, BigNum>> DecryptSum(
//       const PrivateIntersectionSumServerMessage::ServerRoundTwo&
//           server_message);

  Context* ctx_;  // not owned
  std::vector<std::string> elements_;
  std::vector<BigNum> values_;


  // The Paillier private key
  BigNum p_, q_;

  std::unique_ptr<ElGamalEncrypter> elgamal_encrypter_;
  std::unique_ptr<PrivatePaillier> private_paillier_;

  bool protocol_finished_ = false;
};

}  // namespace updatable_private_set_intersection

#endif  // updatable_private_set_intersection_PRIVATE_INTERSECTION_SUM_PARTY_ZERO_IMPL_IMPL_H_
