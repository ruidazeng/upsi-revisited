#include "private_join_and_compute/protocol_party.h"
#include "private_join_and_compute/crypto_tree.h"
#include "private_join_and_compute/crypto_node.h"
#include "private_join_and_compute/crypto/context.h"
#include "private_join_and_compute/crypto/ec_commutative_cipher.h"
#include "private_join_and_compute/crypto/paillier.h"

namespace private_join_and_compute {

ProtocolParty::ProtocolParty() {};

ProtocolParty::ProtocolParty(int id, ProtocolParams params) {
    this->id = id;
    this->params = params;
};

} // namespace private_join_and_compute