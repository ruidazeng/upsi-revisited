#ifndef ProtocolParty_H
#define ProtocolParty_H

#include "updatable_private_set_intersection/crypto_tree.h"
#include "updatable_private_set_intersection/crypto_node.h"
#include "updatable_private_set_intersection/crypto/context.h"
#include "updatable_private_set_intersection/crypto/ec_commutative_cipher.h"
#include "updatable_private_set_intersection/crypto/paillier.h"

namespace updatable_private_set_intersection {

// typedef std::tuple<ECPoint, BigNum> EncryptedElement;
typedef std::tuple<std::string, int> EncryptedElement;

struct ProtocolParams {
    int node_size;
    int stash_size;
    int functionality; // 0 - regular PSI; 1 - cardinality; 2 - sum; 3 - secret shares
    // ElGamal encryption/EC commutative cipher
    BigNum my_pub_key;
    BigNum their_pubkey;
    BigNum my_priv_key;
    // Paillier encryption
    BigNum shared_pub_key;
    BigNum my_shared_priv_key;
};

class ProtocolParty
{
    private:
        // ID (can only be 0 and 1)
        // P_0, P_1
        int id;
        // Each party holds a crypto tree
        CryptoTree crypto_tree;
        // Parameter variable
        ProtocolParams params;
        // TODO: Potential connection info???

    public:
        /// @brief Protocol Party Construction
        ProtocolParty();

        ProtocolParty(int id, ProtocolParams params);


};

}

#endif

