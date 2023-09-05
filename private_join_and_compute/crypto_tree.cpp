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

int CryptoTree::generateLeaf() {
    int lower_bound = 2 * this->depth - 1;

    int upper_bound = 2 * (this->depth + 1) - 2;

    std::random_device rd; // obtain a random number from hardware
    std::mt19937 gen(rd()); // seed the generator - Mersenne Twister
    std::uniform_int_distribution<> distr(lower_bound, upper_bound); // define the range
    return distr(gen);
}

void CryptoTree::generatePath();

void CryptoTree::hashPath();

void CryptoTree::insert();

void CryptoTree::senderUpdateTree();

void CryptoTree::receiverUpdateTree();

