#ifndef Stash_H
#define Stash_H

#include "private_join_and_compute/crypto/big_num.h"
#include "private_join_and_compute/crypto/ec_group.h"
#include "private_join_and_compute/crypto/ec_point.h"
#include "private_join_and_compute/crypto/paillier.h"

#include "crypto"
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



typedef std::tuple<ECGroup, BigNum> EncryptedElement;

class Stash
{
    private:
        int stash_size;

        char[] stash;
        
        
    public:
        Stash();

        Stash(int stash_size);
}


#endif