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

#ifndef PARTYONE_H_
#define PARTYONE_H_

#include "src/google/protobuf/message_lite.h"

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

class PartyOne : public BaseParty {
    public:
        // use base constructor
        using BaseParty::BaseParty;

        PartyOne(PSIParams* params) : BaseParty(params), comm_(params->total_days) {};

        // the methods to define for subclasses
        virtual Status Handle(const ClientMessage& msg, MessageSink<ServerMessage>* sink) = 0;

        // by default this party has no result
        virtual void PrintResult() { }

        void AddComm(const google::protobuf::Message& msg) {
            comm_[current_day] += msg.ByteSizeLong();
        }

        void PrintComm() {
            unsigned long long total = 0;
            for (size_t day = 0; day < comm_.size(); day++) {
                std::cout << "[PartyOne] Day " << std::to_string(day + 1) << " Comm (B):\t";
                std::cout << comm_[day] << std::endl;
                total += comm_[day];
            }
            std::cout << "[PartyOne] Total Comm (B):\t" << total << std::endl;
        }

    protected:
        // each day's comms cost in bytes
        std::vector<int> comm_;
};

class PartyOneNoPayload : public Party<Element, Ciphertext>, public PartyOne {
    public:
        PartyOneNoPayload(PSIParams* params, const std::vector<PartyOneDataset>& datasets) :
            Party<Element, Ciphertext>(params), PartyOne(params), datasets(datasets) {}

        virtual ~PartyOneNoPayload() = default;

        /**
         * update their tree, compute candidates, & send tree updates
         */
        virtual StatusOr<PartyOneMessage::MessageII> GenerateMessageII(
            const PartyZeroMessage::MessageI& msg,
            std::vector<Element> elements
        ) = 0;

        /**
         * delegate incoming messages to other methods
         */
        Status Handle(const ClientMessage& request, MessageSink<ServerMessage>* sink) override;

    protected:
        // one dataset for each day
        std::vector<std::vector<Element>> datasets;
};

class PartyOneWithPayload : public Party<Element, CiphertextAndPayload>, public PartyOne {
    public:
        PartyOneWithPayload(PSIParams* params, const std::vector<PartyOneDataset>& datasets) :
            Party<Element, CiphertextAndPayload>(params), PartyOne(params), datasets(datasets) {}

        virtual ~PartyOneWithPayload() = default;

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
};

class PartyOnePSI : public PartyOneNoPayload {

    public:
        using PartyOneNoPayload::PartyOneNoPayload;

        ~PartyOnePSI() override = default;

        /**
         * update their tree, compute candidates, & send tree updates
         */
        StatusOr<PartyOneMessage::MessageII> GenerateMessageII(
            const PartyZeroMessage::MessageI& msg,
            std::vector<Element> elements
        );
};

class PartyOneCardinality : public PartyOneNoPayload {

    public:
        // use default constructor
        using PartyOneNoPayload::PartyOneNoPayload;

        ~PartyOneCardinality() override = default;

        /**
         * update their tree, compute candidates, & send tree updates
         */
        StatusOr<PartyOneMessage::MessageII> GenerateMessageII(
            const PartyZeroMessage::MessageI& msg,
            std::vector<Element> elements
        );
};

class PartyOneSum : public PartyOneWithPayload {

    public:
        // use default constructor
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
        // use default constructor
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

#endif  // PARTYONE_H_
