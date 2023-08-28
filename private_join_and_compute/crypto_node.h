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

class TreeNode
{
    private:
        int nodeNumber;
        int parentNodeNumber;
        int leftChildNodeNumber;
        int rightChildNodeNumber;

        // decide format of content/payload
        // encryption under el gamal or paillier (ecc points)
        // additon - element/payload (element under private key, payload under paillier)
        std::vector<unsigned char*> content;
        std::vector<unsigned char*> payload;
        
    public:
        TreeNode();
        TreeNode(int nodeNumber);
        TreeNode(int nodeNumber, std::vector<unsigned char> &content);
        TreeNode(int nodeNumber, std::vector<unsigned char> &payload);
        TreeNode(int nodeNumber, std::vector<unsigned char> &content, std::vector<unsigned char> &payload);

        bool hasChildren();
        bool hasParent();

        TreeNode* getParent();
        TreeNode* getChild(int pos);

        int getNodeNumber();
        int getParentNodeNumber();
        int getLeftChildNodeNumber();
        int getRightChildNodeNumberr();

        int getContent();
        int getPayload();

        int setContent();
        int setPayload();

#endif