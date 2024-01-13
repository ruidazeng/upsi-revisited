#pragma once

#include "upsi/addition/party.h"
#include "upsi/network/connection.h"
#include "upsi/network/message_sink.h"
#include "upsi/roles.h"
#include "upsi/network/upsi.pb.h"
#include "upsi/util/data_util.h"
#include "upsi/util/status.inc"
#include "upsi/utils.h"

namespace upsi {
namespace addonly {

class PartyZero : public Client {
    public:
        using Client::Client;

        /**
         * set the datasets variable based on the functionality
         *
         * this can't happen in the constructor for weird inheritance reasons
         */
        virtual void LoadData(const std::vector<Dataset>& datasets) = 0;
};

class PartyZeroNoPayload : public Party<Element, Ciphertext>, public PartyZero {

    public:
        PartyZeroNoPayload(PSIParams* params) :
            Party<Element, Ciphertext>(params), PartyZero(params) {}

        virtual ~PartyZeroNoPayload() = default;

        Status Run(Connection* sink) override;

        void LoadData(const std::vector<Dataset>& datasets) override;

        /**
         * send tree updates & intersection candidates
         */
        Status SendMessageI(MessageSink<ClientMessage>* sink);

        virtual StatusOr<PartyZeroMessage::MessageI> GenerateMessageI(
            std::vector<Element> elements
        ) = 0;

        /**
         * update their tree & compute cardinality
         */
        virtual Status ProcessMessageII(const PartyOneMessage::MessageII& res) = 0;

        /**
         * delegate incoming messages to other methods
         */
        Status Handle(const ServerMessage& res, MessageSink<ClientMessage>* sink) override;

    protected:
        // one dataset for each day
        std::vector<std::vector<Element>> datasets;
};

class PartyZeroPSI : public PartyZeroNoPayload {

    public:
        // use default constructor
        using PartyZeroNoPayload::PartyZeroNoPayload;

        virtual ~PartyZeroPSI() = default;

        StatusOr<PartyZeroMessage::MessageI> GenerateMessageI(
            std::vector<Element> elements
        ) override;

        /**
         * update their tree & compute cardinality
         */
        Status ProcessMessageII(const PartyOneMessage::MessageII& res) override;

        /**
         * print the cardinality & the intersection (if it's small enough)
         */
        void PrintResult() override;

    private:
        // maps g^x to x
        std::map<std::string, std::string> group_mapping;

        // elements in the intersection
        std::vector<std::string> intersection;
};


class PartyZeroCardinality : public PartyZeroNoPayload {

    public:
        // use default constructor
        using PartyZeroNoPayload::PartyZeroNoPayload;

        virtual ~PartyZeroCardinality() = default;

        StatusOr<PartyZeroMessage::MessageI> GenerateMessageI(
            std::vector<Element> elements
        ) override;

        /**
         * update their tree & compute cardinality
         */
        Status ProcessMessageII(const PartyOneMessage::MessageII& res) override;

        /**
         * print cardinality
         */
        void PrintResult() override;

    protected:
        int64_t cardinality = 0;
};


class PartyZeroWithPayload : public Party<ElementAndPayload, Ciphertext>,
                             public PartyZero
{
    public:
        PartyZeroWithPayload(PSIParams* params) :
            Party<ElementAndPayload, Ciphertext>(params), PartyZero(params) {}

        virtual ~PartyZeroWithPayload() = default;

        /**
         * set the datasets variable based on the functionality
         *
         * this can't happen in the constructor for weird inheritance reasons
         */
        void LoadData(const std::vector<Dataset>& datasets) override;

        // set the payload given the element and its associated value
        virtual ElementAndPayload GetPayload(BigNum element, BigNum value) = 0;

        /**
         * send tree updates & intersection candidates
         */
        Status SendMessageI(MessageSink<ClientMessage>* sink);

        virtual StatusOr<PartyZeroMessage::MessageI> GenerateMessageI(
            std::vector<ElementAndPayload> elements
        ) = 0;

        /**
         * update their tree & (optionally) send follow up message
         */
        virtual Status SendMessageIII(
            const PartyOneMessage::MessageII& res,
            MessageSink<ClientMessage>* sink
        ) = 0;

        /**
         * compute the daily output from the other party's last message
         */
        virtual Status ProcessMessageIV(const PartyOneMessage::MessageIV& msg) = 0;

        /**
         * delegate incoming messages to other methods
         */
        Status Handle(const ServerMessage& res, MessageSink<ClientMessage>* sink) override;

    protected:
        // one dataset for each day
        std::vector<std::vector<ElementAndPayload>> datasets;
};

class PartyZeroSum : public PartyZeroWithPayload {

    public:
        PartyZeroSum(PSIParams* params) : PartyZeroWithPayload(params) {
            Status status = decrypter->InitDecryptExp(encrypter->getPublicKey(), MAX_SUM);
            if (!status.ok()) {
                std::cerr << status << std::endl;
                throw std::runtime_error("[PartyOneSum] error initializing exponential elgamal");
            }
        }

        ~PartyZeroSum() override = default;

        // set the payload to be the value
        ElementAndPayload GetPayload(BigNum element, BigNum value) override;

        Status Run(Connection* sink) override;

        StatusOr<PartyZeroMessage::MessageI> GenerateMessageI(
            std::vector<ElementAndPayload> elements
        ) override;

        Status SendMessageIII(
            const PartyOneMessage::MessageII& res,
            MessageSink<ClientMessage>* sink
        ) override;

        Status ProcessMessageIV(const PartyOneMessage::MessageIV& msg) override;

        // print cardinality & sum
        void PrintResult() override;

    private:
        uint64_t sum = 0;
        uint64_t cardinality = 0;
};

class PartyZeroSecretShare : public PartyZeroWithPayload {

    public:
        // use the default constructor
        using PartyZeroWithPayload::PartyZeroWithPayload;

        ~PartyZeroSecretShare() override = default;

        // set the payload to be the element itself
        ElementAndPayload GetPayload(BigNum element, BigNum value) override;

        Status Run(Connection* sink) override;

        StatusOr<PartyZeroMessage::MessageI> GenerateMessageI(
            std::vector<ElementAndPayload> elements
        ) override;

        // sets our share & sends their share out
        Status SendMessageIII(
            const PartyOneMessage::MessageII& res,
            MessageSink<ClientMessage>* sink
        ) override;

        // there is no fourth message for secret share
        Status ProcessMessageIV(const PartyOneMessage::MessageIV& msg) override;

        // print cardinality
        void PrintResult() override;

        // the output secret shares
        std::vector<Element> shares;
};

}  // namespace addonly
}  // namespace upsi
