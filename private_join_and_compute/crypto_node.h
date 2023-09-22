#ifndef CryptoNode_H
#define CryptoNode_H

#include "private_join_and_compute/crypto/ec_commutative_cipher.h"
#include "private_join_and_compute/crypto/paillier.h"


#include <array>
#include <cassert>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <list>
#include <memory>
#include <sstream>
#include <stack>
#include <vector>

namespace private_join_and_compute {

// typedef std::tuple<ECPoint, BigNum> EncryptedElement;
typedef std::tuple<int, int> EncryptedElement;

class CryptoNode
{
    private:
        std::vector<EncryptedElement> node;
        int node_size;

    public:
        // Default constructor
        CryptoNode();

        // Initialize CryptoNode with node size
        CryptoNode(int node_size);

        // Get node size
        int getNodeSize();

        // Get the node vector
        std::vector<EncryptedElement> getNode();

        // Add an element to the node vector, return true if success, false if it's already full
        bool addElement(EncryptedElement enc_elem);
};

} // namespace private_join_and_compute

#endif