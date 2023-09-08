#include "private_join_and_compute/crypto_tree.h"
#include "private_join_and_compute/crypto_node.h"
#include "private_join_and_compute/crypto/context.h"
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


/// @brief Tree Construction

CryptoTree::CryptoTree() {};

CryptoTree::CryptoTree(int stash_size, int node_size) {
    node_size(node_size);
    
    // Index for root node is 0, index for stash node is -1
    CryptoNode root = CryptoNode::CryptoNode(node_size);
    CryptoNode stash = CryptoNode::CryptoNode(stash_size);

    this->crypto_tree.push_back(root);
    this->size += 1;
}

int CryptoTree::getDepth() {
    return this->depth;
}

int CryptoTree::getSize() {
    return this->size;
}


int CryptoTree::getNodeSize() {
    return this->node_size;
}

int CryptoTree::getStashSize() {
    return this->stash_size;
}


/// @brief Helper methods

void CryptoTree::addNewLayer() {
    this->depth += 1;
    int new_size = std::pow(2, this->depth + 1) - 1
    this->crypto_tree.resize(new_size);
}

/// @brief Real methods

// Generate a completley random path
std::vector<CryptoNode> CryptoTree::getPath() {
    Context ctx;
    std::string random_path = ctx.GenerateRandomBytes(32); // 32 bytes for SHA256 => obtain random_path as a byte string
}

// Generate a path based on an element
std::vector<CryptoNode> CryptoTree::getPath(std::string element) {
    Context ctx;
    absl::string_view sv_element = element;
    std::string fixed_path = ctx.Sha256String(sv_element);

}

// Insert a new element
void CryptoTree::insert(std::string);

// Given a path on the tree, replace it with a new path
// Return true if success, false if failure
bool CryptoTree::replacePath(std::vector<CryptoNode> old_path, std::vector<CryptoNode> new_path);

