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
#include "upsi/message_sink.h"
#include "upsi/party.h"
#include "upsi/upsi.pb.h"
#include "upsi/util/status.inc"
#include "upsi/utils.h"

namespace upsi {

class PartyOne : public Party {

    public:
        // use default constructor
        using Party::Party;

        virtual ~PartyOne() = default;

        // the methods to define for subclasses
        virtual Status Handle(const ClientMessage& msg, MessageSink<ServerMessage>* sink) = 0;

        // by default party one has no output
        virtual void PrintResult() { }
};


class PartyOneWithPayload : public PartyOne {
    public:
        PartyOneWithPayload(
            Context* ctx,
            std::string epk_fn,
            std::string esk_fn,
            std::string psk_fn,
            const std::vector<PartyOneDataset>& datasets,
            int total_days
        ) : PartyOne(ctx, epk_fn, esk_fn, psk_fn, total_days), datasets(datasets) { }

        ~PartyOneWithPayload() override = default;

        /**
         * update their tree, compute candidates, & send tree updates
         */
        StatusOr<PartyOneMessage::MessageII> GenerateMessageII(
            const PartyZeroMessage::MessageI& msg,
            std::vector<Element> elements
        );

        /**
         * process the last incoming message & (optionally) respond
         */
        virtual StatusOr<PartyOneMessage::MessageIV> ProcessMessageIII(
            const PartyZeroMessage::MessageIII& msg
        ) = 0;

    protected:
        // one dataset for each day
        std::vector<std::vector<Element>> datasets;

        // our plaintext tree & their encrypted tree
        CryptoTree<Element> my_tree;
        CryptoTree<CiphertextAndPayload> other_tree;
};

class PartyOneCardinality : public PartyOne {
    public:
        PartyOneCardinality(
            Context* ctx,
            std::string epk_fn,
            std::string esk_fn,
            std::string psk_fn,
            const std::vector<PartyOneDataset>& datasets,
            int total_days
        ) : PartyOne(ctx, epk_fn, esk_fn, psk_fn, total_days), datasets(datasets) { }

        ~PartyOneCardinality() override = default;

        /**
         * update their tree, compute candidates, & send tree updates
         */
        StatusOr<PartyOneMessage::MessageII> GenerateMessageII(
            const PartyZeroMessage::MessageI& msg,
            std::vector<Element> elements
        );

        /**
         * delegate incoming messages to other methods
         */
        Status Handle(const ClientMessage& request, MessageSink<ServerMessage>* sink) override;

    protected:
        // one dataset for each day
        std::vector<std::vector<Element>> datasets;

        // our plaintext tree & their encrypted tree
        CryptoTree<Element> my_tree;
        CryptoTree<Ciphertext> other_tree;
};

class PartyOneSum : public PartyOneWithPayload {

    public:
        // use the default constructor
        using PartyOneWithPayload::PartyOneWithPayload;

        /**
         * receive our secret shares
         */
        StatusOr<PartyOneMessage::MessageIV> ProcessMessageIII(
            const PartyZeroMessage::MessageIII& msg
        ) override;

        /**
         * delegate incoming messages to other methods
         */
        Status Handle(const ClientMessage& request, MessageSink<ServerMessage>* sink) override;
};

class PartyOneSecretShare : public PartyOneWithPayload {

    public:
        // use the default constructor
        using PartyOneWithPayload::PartyOneWithPayload;

        // the output secret shares
        std::vector<Element> shares;

        /**
         * receive our secret shares
         */
        StatusOr<PartyOneMessage::MessageIV> ProcessMessageIII(
            const PartyZeroMessage::MessageIII& msg
        ) override;

        /**
         * delegate incoming messages to other methods
         */
        Status Handle(const ClientMessage& request, MessageSink<ServerMessage>* sink) override;
};

}  // namespace upsi

#endif  // PARTYONE_IMPL_H_
