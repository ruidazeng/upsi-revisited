#ifndef CryptoNode_H
#define CryptoNode_H

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

class CryptoNode
{
    private:
        bool isRoot;
        bool isLeaf;

        // int layer = 0;

        // int nodesize;
        int nodeNumber; // 0 for root, -1 for stash
        int parentNodeNumber;
        int leftChildNodeNumber;
        int rightChildNodeNumber;

        // decide format of content/payload
        // encryption under el gamal or paillier (ecc points)
        // additon - element/payload (element under private key, payload under paillier)
        std::vector<unsigned char*> content;
        std::vector<unsigned char*> payload;
        
        void makeRoot();
        void makeNotRoot();
        
    public:
        CryptoNode();
        CryptoNode(int nodeNumber);
        CryptoNode(int nodeNumber, std::vector<unsigned char> &content);
        CryptoNode(int nodeNumber, std::vector<unsigned char> &payload);
        CryptoNode(int nodeNumber, std::vector<unsigned char> &content, std::vector<unsigned char> &payload);

        bool isRoot();
        bool isLeaf();

        void makeLeaf();
        void makeNotLeaf();

        int getNodeNumber();
        int getParentNodeNumber();
        int getLeftChildNodeNumber();
        int getRightChildNodeNumberr();

        std::vector<unsigned char*> getContent();
        std::vector<unsigned char*> getPayload();

        std::vector<unsigned char*> setContent(std::vector<unsigned char> &content);
        std::vector<unsigned char*> setPayload(std::vector<unsigned char> &payload);
}

#endif