#include "updatable_private_set_intersection/protocol_party.h"
#include "updatable_private_set_intersection/crypto_tree.h"
#include "updatable_private_set_intersection/crypto_node.h"
#include "updatable_private_set_intersection/crypto/context.h"
#include "updatable_private_set_intersection/crypto/ec_commutative_cipher.h"
#include "updatable_private_set_intersection/crypto/paillier.h"

namespace updatable_private_set_intersection {

ProtocolParty::ProtocolParty() {};

ProtocolParty::ProtocolParty(int id, ProtocolParams params) {
    this->id = id;
    this->params = params;
};

} // namespace updatable_private_set_intersection