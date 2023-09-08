#include "crypto_tree.h"

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


CryptoTree::CryptoTree() {};

CryptoTree::CryptoTree(int stash_size, int node_size) {
    node_size(node_size);
    
    // Index for root node is 0, index for stash node is -1
    CryptoNode root = CryptoNode::CryptoNode(node_size);
    CryptoNode stash = CryptoNode::CryptoNode(stash_size));

    this->crypto_tree.push_back(root);
    this->size += 1;
}

void CryptoTree::addNewLayer() {
    this->depth += 1;
    int new_size = std::pow(2, this->depth + 1) - 1
    this->crypto_tree.resize(new_size);
}

void CryptoTree::insert();

void CryptoTree::senderUpdateTree();

void CryptoTree::receiverUpdateTree();

