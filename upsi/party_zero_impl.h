#ifndef PARTYZERO_IMPL_H_
#define PARTYZERO_IMPL_H_

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "upsi/crypto/context.h"
#include "upsi/crypto/ec_commutative_cipher.h"
#include "upsi/crypto/elgamal.h"
#include "upsi/crypto/threshold_paillier.h"
#include "upsi/crypto_tree.h"
#include "upsi/data_util.h"
#include "upsi/match.pb.h"
#include "upsi/message_sink.h"
#include "upsi/party_impl.h"
#include "upsi/private_intersection.pb.h"
#include "upsi/protocol_client.h"
#include "upsi/upsi.pb.h"
#include "upsi/util/status.inc"
#include "upsi/utils.h"

namespace upsi {

// This class represents the "party 0" part of the updatable private set intersection protocol.
// This is the party that will receive the output in one-sided UPSI.

class PartyZeroImpl : public ProtocolClient, PartyImpl<PartyZeroDataset> {
    public:
        PartyZeroImpl(
            Context* ctx,
            std::string epk_fn,
            std::string esk_fn,
            std::string psk_fn,
            const std::vector<PartyZeroDataset>& d,
            int total_days
        ) : PartyImpl(ctx, epk_fn, esk_fn, psk_fn, d, total_days), 
            sum_ciphertext(ctx->Zero()) { } 

        ~PartyZeroImpl() override = default;

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

        StatusOr<PartyZeroMessage::MessageIII> GenerateMessageIII(
            std::vector<CiphertextAndPayload> candidates
        );

        /**
         * compute the daily output from the other party's last message
         */
        Status ProcessMessageIV(const PartyOneMessage::MessageIV& msg);

        /**
         * delegate incoming messages to other methods
         */
        Status Handle(const ServerMessage& res, MessageSink<ClientMessage>* sink) override;

        /**
         * protocol is finished when we've gone through all days
         */
        bool protocol_finished() override { 
            return (this->current_day == this->total_days);
        }

        int64_t cardinality = 0;
        uint64_t sum = 0;

    private:
        // our plaintext tree & their encrypted tree
        CryptoTree<ElementAndPayload> my_tree;
        CryptoTree<Ciphertext> other_tree;

        // TODO: move this
        BigNum sum_ciphertext;
};

}  // namespace upsi

#endif  // PARTYZERO_IMPL_H_
