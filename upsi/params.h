#pragma once

#include "upsi/crypto/context.h"
#include "upsi/utils.h"

namespace upsi {

struct PSIParams {

    // pointer to the running context object
    Context* ctx;

    // filename for el gamal (shared) public key
    std::string epk_fn;

    // filename for el gamal secret key
    std::string esk_fn;

    // filename for paillier public key
    std::string ppk_fn;

    // filename for paillier secret key
    std::string psk_fn;

    // number of days to run protocol for
    int total_days;

    // parameters for the CryptoTrees
    int stash_size = DEFAULT_STASH_SIZE;
    int node_size = DEFAULT_NODE_SIZE;

    // filename for this party's initial plaintext tree
    std::string my_tree_fn;

    // filename for other party's initial encrypted tree
    std::string other_tree_fn;

    // filename for initial oprf outputs
    std::string oprf_fn;
    
    int start_size = -1;

    // addition only param set
    PSIParams(
        Context* ctx,
        std::string epk_fn,
        std::string esk_fn,
        std::string psk_fn,
        int total_days,
        std::string my_tree_fn = "",
        std::string other_tree_fn = ""
    ) : ctx(ctx), epk_fn(epk_fn), esk_fn(esk_fn), psk_fn(psk_fn), total_days(total_days),
        my_tree_fn(my_tree_fn), other_tree_fn(other_tree_fn) { }

    // addition & deletion param set
    PSIParams(
        Context* ctx,
        std::string ppk_fn,
        std::string psk_fn,
        int total_days,
        std::string my_tree_fn = "",
        std::string other_tree_fn = ""
    ) : ctx(ctx), ppk_fn(ppk_fn), psk_fn(psk_fn), total_days(total_days),
        my_tree_fn(my_tree_fn), other_tree_fn(other_tree_fn) { }

    // original construction param set
    PSIParams(
        bool nonce,
        Context* ctx,
        std::string my_pk_fn,
        std::string their_pk_fn,
        std::string sk_fn,
        int total_days,
        std::string my_tree_fn = "",
        std::string other_tree_fn = "",
        std::string oprf_fn = ""
    ) : ctx(ctx), epk_fn(my_pk_fn), esk_fn(sk_fn), ppk_fn(their_pk_fn), total_days(total_days),
        my_tree_fn(my_tree_fn), other_tree_fn(other_tree_fn), oprf_fn(oprf_fn) { }


    // true when we are importing initial trees from file
    bool ImportTrees() {
        return my_tree_fn != "";
    }
};

}
