// Cryptographic Tree Implementation
// Based on Microsoft's Merkle Tree

// Finished Tasks:
// 1. Node structures (TODO - structures of the elements/contents)
// 2. Tree structures (TODO - encryption of nodes)
// 3. Hash structures (Figure out if this is acceptable? If not replace)
// - Ruida

// TODO:
// 1. Finish writing get_path()
// 2. Finishwriting insert()
// 3. Add UpdateTree functionality (need to be multiparty)
// 4. Elements need to be encrypted (using AES or similar)
// - Ruida

// Questions:
// 1. How to achieve multiparty?
// 2. Serialization/Deserialization of the tree and hashes for MPC

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


// Cryptographic Tree Structures

 class TreeT
  {
  protected:
    /// @brief The structure of tree nodes
    struct Node
    {
      /// @brief Constructs a new tree node
      static Node* make()
      {
        auto r = new Node();
        r->left = r->right = nullptr;
        r->update_sizes();
        return r;
      }

      /// @brief Constructs a new tree node
      /// @param left The left child of the new node
      /// @param right The right child of the new node
      static Node* make(Node* left, Node* right)
      {
        assert(left && right);
        auto r = new Node();
        r->left = left;
        r->right = right;
        r->update_sizes();
        return r;
      }

      ~Node()
      {
        delete (left);
        delete (right);
      }
    
          /// @brief Updates the tree size and height of the subtree under a node
      void update_sizes()
      {
        if (left && right)
        {
          depth = std::max(left->depth, right->depth) + 1;
        }
        else
          depth = 1;
      }

      /// @brief The left child of the node
      Node* left;

      /// @brief The right child of the node
      Node* right;

      /// @brief The depth of the subtree
      uint8_t depth;
    };

    // Tree
    /// @brief Current root node of the tree
    Node* _root = nullptr;

    /// @brief Current stash node of the tree
    Node* _stash = nullptr;

    /// @brief The node size of the tree
    uint8_t node_size;

    /// @brief The max stash of the subtree
    uint8_t max_stash;

  public:

    /// @brief Constructs an empty tree
    TreeT() {}

    /// @brief Copies a tree
    TreeT(const TreeT& other)
    {
      *this = other;
    }

    /// @brief Constructs a tree containing one root
    /// @param node_size the node size of the tree
    TreeT(const uint8_t node_size)
    {
        this->node_size = node_size;
        this->max_stash = 0;
        Node* root = make();
        Node* stash = make();
        // TODO: Do I need to call insert()?
        this->_root = root;
        this->_stash = stash;
    }

    /// @brief Deconstructor
    ~TreeT()
    {
      delete (_root);
      // TODO: Iterative deletion
    }

    /// @brief Inserts an element into the tree
    /// @param element element to be inserted
    void insert(const auto element)
    {
        // TODO: auto insertion
    }

    /// @brief Sender adds input element to encrypted tree with stash held
    /// by receiver. Sender has secret key and both parties have the public key
    /// @param x input element
    /// @param p optional payload
    /// @param sk secret key
    /// @param D encrypted tree
    /// @param S stash
    /// @param pk public key
    void updateTree()
    {
        // TODO
    }

    /// @brief Walks along the path from the root of a tree to a leaf
    /// @param index The leaf index to walk to
    /// @param update Flag to enable re-computation of node fields (like
    /// subtree size) while walking
    /// @param f Function to call for each node on the path; the Boolean
    /// indicates whether the current step is a right or left turn.
    /// @return The final leaf node in the walk
    inline Node* walk_to(
      size_t index, bool update, const std::function<bool(Node*&, bool)>&& f)
    {
      if (index < min_index() || max_index() < index)
        throw std::runtime_error("invalid leaf index");

      compute_root();

      assert(index < _root->size);

      Node* cur = _root;
      size_t it = 0;
      if (_root->height > 1)
        it = index << (sizeof(index) * 8 - _root->height + 1);
      assert(walk_stack.empty());

      for (uint8_t height = _root->height; height > 1;)
      {
        assert(cur->invariant());
        bool go_right = (it >> (8 * sizeof(it) - 1)) & 0x01;
        if (update)
          walk_stack.push_back(cur);
        if (cur->height == height)
        {
          if (!f(cur, go_right))
            continue;
          cur = (go_right ? cur->right : cur->left);
        }
        it <<= 1;
        height--;
      }

      if (update)
        while (!walk_stack.empty())
        {
          walk_stack.back()->update_sizes();
          walk_stack.pop_back();
        }

      return cur;
    }

    /// @brief Extracts the path from a leaf index to the root of the tree
    /// @param index The leaf index of the path to extract
    /// @return The path
    std::shared_ptr<Path> path(size_t index)
    {
      statistics.num_paths++;
      std::list<typename Path::Element> elements;

      walk_to(index, false, [&elements](Node* n, bool go_right) {
        typename Path::Element e;
        e.hash = go_right ? n->left->hash : n->right->hash;
        e.direction = go_right ? Path::PATH_LEFT : Path::PATH_RIGHT;
        elements.push_front(std::move(e));
        return true;
      });

      return std::make_shared<Path>(
        leaf_node(index)->hash, index, std::move(elements), max_index());
    }

  };



/// @brief Template for fixed-size hashes
/// From Microsoft Merkle Tree

  /// @tparam SIZE Size of the hash in number of bytes
  template <size_t SIZE>
  struct HashT
  {
    /// Holds the hash bytes
    uint8_t bytes[SIZE];

    /// @brief Constructs a Hash with all bytes set to zero
    HashT<SIZE>()
    {
      std::fill(bytes, bytes + SIZE, 0);
    }

    /// @brief Constructs a Hash from a byte buffer
    /// @param bytes Buffer with hash value
    HashT<SIZE>(const uint8_t* bytes)
    {
      std::copy(bytes, bytes + SIZE, this->bytes);
    }

    /// @brief Constructs a Hash from a string
    /// @param s String to read the hash value from
    HashT<SIZE>(const std::string& s)
    {
      if (s.length() != 2 * SIZE)
        throw std::runtime_error("invalid hash string");
      for (size_t i = 0; i < SIZE; i++)
      {
        int tmp;
        sscanf(s.c_str() + 2 * i, "%02x", &tmp);
        bytes[i] = tmp;
      }
    }

    /// @brief The size of the hash (in number of bytes)
    size_t size() const
    {
      return SIZE;
    }

    /// @brief zeros out all bytes in the hash
    void zero()
    {
      std::fill(bytes, bytes + SIZE, 0);
    }

    /// @brief Convert a hash to a hex-encoded string
    /// @param num_bytes The maximum number of bytes to convert
    /// @param lower_case Enables lower-case hex characters
    std::string to_string(size_t num_bytes = SIZE, bool lower_case = true) const
    {
      size_t num_chars = 2 * num_bytes;
      std::string r(num_chars, '_');
      for (size_t i = 0; i < num_bytes; i++)
        snprintf(
          const_cast<char*>(r.data() + 2 * i),
          num_chars + 1 - 2 * i,
          lower_case ? "%02x" : "%02X",
          bytes[i]);
      return r;
    }

    /// @brief Hash assignment operator
    HashT<SIZE> operator=(const HashT<SIZE>& other)
    {
      std::copy(other.bytes, other.bytes + SIZE, bytes);
      return *this;
    }

    /// @brief Hash equality operator
    bool operator==(const HashT<SIZE>& other) const
    {
      return memcmp(bytes, other.bytes, SIZE) == 0;
    }

    /// @brief Hash inequality operator
    bool operator!=(const HashT<SIZE>& other) const
    {
      return memcmp(bytes, other.bytes, SIZE) != 0;
    }
  };