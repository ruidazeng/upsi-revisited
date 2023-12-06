#ifndef PARTYZERO_IMPL_H_
#define PARTYZERO_IMPL_H_

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
#include "upsi/match.pb.h"
#include "upsi/message_sink.h"
#include "upsi/party.h"
#include "upsi/private_intersection.pb.h"
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
};

class PartyZeroWithPayload : public PartyZero {
    public:
        // use default constructor
        using PartyZero::PartyZero;

        virtual ~PartyZeroWithPayload() = default;

        /**
         * set the datasets variable based on the functionality
         *
         * this can't happen in the constructor for weird inheritance reasons
         */
        void LoadData(const std::vector<PartyZeroDataset>& datasets) override;

        // set the payload given the element and its associated value
        virtual ElementAndPayload GetPayload(BigNum element, BigNum value) = 0;

        /**
         * send tree updates & intersection candidates
         */
        Status SendMessageI(MessageSink<ClientMessage>* sink);

        StatusOr<PartyZeroMessage::MessageI> GenerateMessageI(
            std::vector<ElementAndPayload> elements
        );

        /**
         * update their tree & (optionally) send follow up message
         */
        Status SendMessageIII(
            const PartyOneMessage::MessageII& res,
            MessageSink<ClientMessage>* sink
        );

        virtual StatusOr<PartyZeroMessage::MessageIII> GenerateMessageIII(
            std::vector<CiphertextAndPayload> candidates
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

        // our plaintext tree & their encrypted tree
        CryptoTree<ElementAndPayload> my_tree;
        CryptoTree<Ciphertext> other_tree;
};

class PartyZeroCardinality : public PartyZero {

    public:
        // use default constructor
        using PartyZero::PartyZero;

        virtual ~PartyZeroCardinality() = default;

        /**
         * set the datasets variable based on the functionality
         *
         * this can't happen in the constructor for weird inheritance reasons
         */
        void LoadData(const std::vector<PartyZeroDataset>& datasets);

        Status Run(Connection* sink) override;

        /**
         * send tree updates & intersection candidates
         */
        Status SendMessageI(MessageSink<ClientMessage>* sink);

        StatusOr<PartyZeroMessage::MessageI> GenerateMessageI(
            std::vector<Element> elements
        );

        /**
         * update their tree & compute cardinality
         */
        Status ProcessMessageII(const PartyOneMessage::MessageII& res);

        /**
         * print cardinality
         */
        void PrintResult() override;

        /**
         * delegate incoming messages to other methods
         */
        Status Handle(const ServerMessage& res, MessageSink<ClientMessage>* sink) override;

    protected:
        // one dataset for each day
        std::vector<std::vector<Element>> datasets;

        // our plaintext tree & their encrypted tree
        CryptoTree<Element> my_tree;
        CryptoTree<Ciphertext> other_tree;

        int64_t cardinality = 0;
};

class PartyZeroSum : public PartyZeroWithPayload {

    public:
        PartyZeroSum(
            Context* ctx,
            std::string epk_fn,
            std::string esk_fn,
            std::string psk_fn,
            int total_days
        ) : PartyZeroWithPayload(ctx, epk_fn, esk_fn, psk_fn, total_days), 
            sum_ciphertext(ctx->Zero()) { }

        ~PartyZeroSum() override = default;

        // set the payload to be the value
        ElementAndPayload GetPayload(BigNum element, BigNum value) override;

        Status Run(Connection* sink) override;

        // TODO: what does this do?
        StatusOr<PartyZeroMessage::MessageIII> GenerateMessageIII(
            std::vector<CiphertextAndPayload> candidates
        ) override;

        Status ProcessMessageIV(const PartyOneMessage::MessageIV& msg) override;

        // print cardinality & sum
        void PrintResult() override;

    private:
        // TODO: is this really necessary?
        BigNum sum_ciphertext;

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

        // sets our share & sends their share out
        StatusOr<PartyZeroMessage::MessageIII> GenerateMessageIII(
            std::vector<CiphertextAndPayload> candidates
        ) override;

        // there is no fourth message for secret share
        Status ProcessMessageIV(const PartyOneMessage::MessageIV& msg) override;

        // print cardinality 
        void PrintResult() override;

        // the output secret shares
        std::vector<Element> shares;
};

}  // namespace upsi

#endif  // PARTYZERO_IMPL_H_
