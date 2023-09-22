#include "private_join_and_compute/crypto_tree.h"
#include "private_join_and_compute/crypto_node.h"
#include "private_join_and_compute/crypto/context.h"
#include "private_join_and_compute/crypto/ec_commutative_cipher.h"
#include "private_join_and_compute/crypto/paillier.h"

#include <bitset>
#include <vector>
#include <cmath>


/// @brief Tree Construction

namespace private_join_and_compute {

CryptoTree::CryptoTree() {};

CryptoTree::CryptoTree(int stash_size, int node_size) {
    this->node_size = node_size;
    this->stash_size = node_size;
    
    // Index for root node is 0, index for stash node is -1
    CryptoNode stash = CryptoNode(stash_size);
    CryptoNode root = CryptoNode(node_size);

    this->stash = stash;
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
    int new_size = std::pow(2, this->depth + 1) - 1;
    this->crypto_tree.resize(new_size);
}

std::string CryptoTree::binaryHash(std::string const &byte_hash) {
    std::string binary_hash = "";
    for (char const &c: byte_hash) {
        binary_hash += std::bitset<8>(c).to_string();
    }
    return binary_hash;
}


std::vector<CryptoNode> CryptoTree::findPath(int depth, std::string binary_hash) {
    std::vector<CryptoNode> path;
    
    int node = 0; // root
    path.push_back(this->crypto_tree[node]);

    for (int i=0; i <= depth; ++i) {
        if (binary_hash[i] == '0') {
            node = node * 2 + 1;
        }
        else if (binary_hash[i] == '1') {
            node = node * 2 + 2;
        }
        path.push_back(this->crypto_tree[node]);
    }
    return path;
}

/// @brief Real methods

// Generate a completley random path
std::vector<CryptoNode> CryptoTree::getPath() {
    Context ctx;
    std::string random_path = ctx.GenerateRandomBytes(32); // 32 bytes for SHA256 => obtain random_path as a byte string
    std::string random_path_binary = this->binaryHash(random_path);

    // Find path in tree
    auto tree_path = this->findPath(this->depth, random_path_binary);
    return tree_path;
}

// Generate a path based on an element
std::vector<CryptoNode> CryptoTree::getPath(std::string element) {
    Context ctx;
    absl::string_view sv_element = element;
    // TODO: PRF?????
    std::string fixed_path = ctx.Sha256String(sv_element);
    std::string fixed_path_binary = this->binaryHash(fixed_path);

    // Find path in tree
    auto tree_path = this->findPath(this->depth, fixed_path_binary);
    return tree_path;
}

// Insert a new element
// TODO: WHEN TO ADD A NEW LEVEL OF TREE???
void CryptoTree::insert(std::string element) {
    // find the path based on hash
    auto old_path = this->getPath(element);
    // gather every element in the path + stash
    std::vector<EncryptedElement> pathstash;

    // find the leaf node  of the path based on depth

    // construct the new path

    // replace the old path with the new path

    // replace the old stash with the new stash

}

// Given a leaf node on the tree, replace the root to leaf path with a new path
// Return true if success, false if failure
bool CryptoTree::replacePath(int leaf, std::vector<CryptoNode> new_path) {
    int node_index = leaf;
    int path_index = new_path.size();
    while (node_index != 0 || path_index != -1) {
        this->crypto_tree[node_index] = new_path[path_index];
        // find parent and update indexes
        node_index = std::floor((node_size - 1)/2);
        path_index -= 1;
    }
    if (node_index == 0 && path_index == 1) {
        return true;
    }
    else {
        return false;
    }
}

} // namespace private_join_and_compute