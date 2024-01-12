#ifndef PARTYZERO_H_
#define PARTYZERO_H_

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "upsi/connection.h"
#include "upsi/crypto/context.h"
#include "upsi/crypto/ec_commutative_cipher.h"
#include "upsi/crypto/elgamal.h"
#include "upsi/crypto/threshold_paillier.h"
#include "upsi/crypto_tree.h"
#include "upsi/data_util.h"
#include "upsi/message_sink.h"
#include "upsi/party.h"
#include "upsi/upsi.pb.h"
#include "upsi/util/status.inc"
#include "upsi/utils.h"

namespace upsi {

class PartyZero : public Party {

    public:
        // use default constructor
        using Party::Party;

        virtual ~PartyZero() = default;

        // the methods to define for subclasses
        virtual void LoadData(const std::vector<PartyZeroDataset>& datasets) = 0;
        virtual Status Run(Connection* sink) = 0;
        virtual Status Handle(const ServerMessage& msg, MessageSink<ClientMessage>* sink) = 0;
        virtual void PrintResult() = 0;
        virtual void UpdateResult(uint64_t cur_ans) = 0;
};

class PartyZeroCASUM : public PartyZero {
    public:
        // use default constructor
        using PartyZero::PartyZero;

        virtual ~PartyZeroCASUM() = default;

        /**
         * set the datasets variable based on the functionality
         *
         * this can't happen in the constructor for weird inheritance reasons
         */
        void LoadData(const std::vector<PartyZeroDataset>& datasets) override;

        // set the payload given the element and its associated value
        virtual ElementAndPayload GetPayload(BigNum element, BigNum value) = 0;
        
        Status Run(Connection* sink) override;

        /**
         * send tree updates & intersection candidates
         */
        Status SendMessageI(MessageSink<ClientMessage>* sink);

        StatusOr<PartyZeroMessage::MessageI> GenerateMessageI(
            std::vector<ElementAndPayload> elements
        );

        /**
         * update their tree & send follow up message
         */
        Status ProcessMessageII(
            const PartyOneMessage::MessageII& res,
            MessageSink<ClientMessage>* sink
        );
        

        /**
         * delegate incoming messages to other methods
         */
        Status Handle(const ServerMessage& res, MessageSink<ClientMessage>* sink) override;
        
        void PrintResult() override;
        
        void UpdateResult(uint64_t cur_ans) override;

    protected:
        // one dataset for each day
        std::vector<std::vector<ElementAndPayload>> datasets;

        uint64_t result = 0;
};

class PartyZeroCardinality : public PartyZeroCASUM {

    public:
        // use default constructor
        using PartyZeroCASUM::PartyZeroCASUM;

        virtual ~PartyZeroCardinality() = default;
		
		ElementAndPayload GetPayload(BigNum element, BigNum value) override;
        
};

class PartyZeroSum : public PartyZeroCASUM {

    public:
        using PartyZeroCASUM::PartyZeroCASUM;

        ~PartyZeroSum() override = default;

        // set the payload to be the value
        ElementAndPayload GetPayload(BigNum element, BigNum value) override;

};

}  // namespace upsi

#endif  // PARTYZERO_H_
