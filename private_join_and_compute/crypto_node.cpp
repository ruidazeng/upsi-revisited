#include "crypto_node.h"

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

CryptoNode::CryptoNode() {};

CryptoNode::CryptoNode(int nodeNumber) {
    nodeNumber(nodeNumber);
    // if (nodeNumber == 0): this->makeRoot();
}

CryptoNode::CryptoNode(int nodeNumber, std::vector<unsigned char> &content) {
    nodeNumber(nodeNumber);
    content(content);
    // if (nodeNumber == 0): this->makeRoot();
}

CryptoNode::CryptoNode(int nodeNumber, std::vector<unsigned char> &payload) {
    nodeNumber(nodeNumber);
    payload(payload);
    // if (nodeNumber == 0): this->makeRoot();
}

CryptoNode::CryptoNode(int nodeNumber, std::vector<unsigned char> &content, std::vector<unsigned char> &payload) {
    nodeNumber(nodeNumber);
    content(content);
    payload(payload);
    // if (nodeNumber == 0): this->makeRoot();
}

// bool CryptoNode::isRoot() {
//     return this->isRoot;
// }

// bool CryptoNode::isLeaf() {
//     return this->isLeaf;
// }

// void CryptoNode::makeRoot() {
//     this->isRoot = true;
// }

// void CryptoNode::makeNotRoot() {
//     this->isRoot = false;
// }

// void CryptoNode::makeLeaf() {
//     this->isLeaf = true;
// }

// void CryptoNode::makeNotLeaf() {
//     this->isLeaf = false;
// }

int CryptoNode::getNodeNumber() {
    return this->nodeNumber;
}

// int CryptoNode::getParentNodeNumber() {
//     return this->parentNodeNumber;
// }

// int CryptoNode::getLeftChildNodeNumber() {
//     return this->leftChildNodeNumber;
// }

// int CryptoNode::getRightChildNodeNumberr() {
//     return this->rightChildNodeNumber;
// }

std::vector<unsigned char*> CryptoNode::getContent() {
    return this->content;
}

std::vector<unsigned char*> CryptoNode::getPayload() {
    return this->payload;
}

std::vector<unsigned char*> CryptoNode::setContent(std::vector<unsigned char> &content) {
    this->content = content;
    return this->content;
}

std::vector<unsigned char*> CryptoNode::setPayload(std::vector<unsigned char> &payload) {
    this->payload = payload;
    return this->payload;
}
