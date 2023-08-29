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

CryptoTree::CryptoTree(int nodeNumber) {
    nodeNumber(nodeNumber);
    // if (nodeNumber == 0): this->makeRoot();
}

CryptoTree::CryptoTree(int nodeNumber, std::vector<unsigned char> &content) {
    nodeNumber(nodeNumber);
    content(content);
    // if (nodeNumber == 0): this->makeRoot();
}

CryptoTree::CryptoTree(int nodeNumber, std::vector<unsigned char> &payload) {
    nodeNumber(nodeNumber);
    payload(payload);
    // if (nodeNumber == 0): this->makeRoot();
}

CryptoTree::CryptoTree(int nodeNumber, std::vector<unsigned char> &content, std::vector<unsigned char> &payload) {
    nodeNumber(nodeNumber);
    content(content);
    payload(payload);
    // if (nodeNumber == 0): this->makeRoot();
}

bool CryptoTree::isRoot() {
    return this->isRoot;
}

bool CryptoTree::isLeaf() {
    return this->isLeaf;
}

void CryptoTree::makeRoot() {
    this->isRoot = true;
}

void CryptoTree::makeNotRoot() {
    this->isRoot = false;
}

void CryptoTree::makeLeaf() {
    this->isLeaf = true;
}

void CryptoTree::makeNotLeaf() {
    this->isLeaf = false;
}

int CryptoTree::getNodeNumber() {
    return this->nodeNumber;
}

int CryptoTree::getParentNodeNumber() {
    return this->parentNodeNumber;
}

int CryptoTree::getLeftChildNodeNumber() {
    return this->leftChildNodeNumber;
}

int CryptoTree::getRightChildNodeNumberr() {
    return this->rightChildNodeNumber;
}

std::vector<unsigned char*> CryptoTree::getContent() {
    return this->content;
}

std::vector<unsigned char*> CryptoTree::getPayload() {
    return this->payload;
}

std::vector<unsigned char*> CryptoTree::setContent(std::vector<unsigned char> &content) {
    this->content = content;
    return this->content;
}

std::vector<unsigned char*> CryptoTree::setPayload(std::vector<unsigned char> &payload) {
    this->payload = payload;
    return this->payload;
}
