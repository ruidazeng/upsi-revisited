#include "private_join_and_compute/crypto_node.h"

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

// Default constructor
CryptoNode::CryptoNode() {};

// Initialize CryptoNode with node size
CryptoNode::CryptoNode(int node_size) {
    this->node_size = node_size;
}

// Get node size
int CryptoNode::getNodeSize() {
    return this->node_size;
}

// Get the node vector
std::vector<EncryptedElement> CryptoNode::getNode() {
    return this->node;
}

// Add an encrypted element to the node vector, return true if success, false if it's already full
bool CryptoNode::addElement(EncryptedElement enc_elem) {
    if (this->node.size() >= this->node_size) {
        return false;
    }
    else {
        this->node.push_back(enc_elem);
        return true;
    }
}

} // namespace private_join_and_compute