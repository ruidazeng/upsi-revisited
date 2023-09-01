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

