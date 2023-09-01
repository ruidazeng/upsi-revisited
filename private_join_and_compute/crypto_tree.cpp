#include "crypto_tree.h"

#include <array>
#include <cassert>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <list>
#include <memory>
#include <sstream>
#include <stack>
#include <vector>


CryptoTree::CryptoTree() {};

CryptoTree::CryptoTree(int node_size) {
    node_size(node_size);
    
    CryptoNode root = CryptoNode::CryptoNode(0);
    CryptoNode stash = CryptoNode::CryptoNode(-1);

    this->crypto_tree.push_back(root);
    this->size += 1;
}

void CryptoTree::addNewLayer() {
    this->depth += 1;
    int new_size = std::pow(2, this->depth + 1) - 1
    this->crypto_tree.resize(new_size);
}

void CryptoTree::generateNextPath() {


}

void CryptoTree::generatePath();

void CryptoTree::insert();

void CryptoTree::senderUpdateTree();

void CryptoTree::receiverUpdateTree();

