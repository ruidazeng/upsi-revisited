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

		virtual void LoadData(const std::vector<PartyOneDataset>& datasets) = 0;
        // the methods to define for subclasses
        virtual Status Handle(const ClientMessage& msg, MessageSink<ServerMessage>* sink) = 0;

        // by default party one has no output
        virtual void PrintResult() { }
        
        bool day_finished;
};

class PartyOneCASUM : public PartyOne {
    public:
        using PartyOne::PartyOne;

        ~PartyOneCASUM() override = default;
        
        void LoadData(const std::vector<PartyOneDataset>& datasets) override;
        
        ElementAndPayload GetPayload(BigNum element);

        /**
         * update their tree, compute candidates, & send tree updates
         */
        StatusOr<PartyOneMessage::MessageII> GenerateMessageII(
            const PartyZeroMessage::MessageI& msg,
            std::vector<ElementAndPayload> elements
        );
        
        Status Handle(const ClientMessage& request, MessageSink<ServerMessage>* sink) override;

    protected:
        // one dataset for each day
        std::vector<std::vector<ElementAndPayload>> datasets;

};


}  // namespace upsi

#endif  // PARTYONE_H_
