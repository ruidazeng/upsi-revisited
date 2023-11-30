# UPSI Project

## How to run the protocol

In order to run Updatable Private Set Intersection, you need to install Bazel, if you
don't have it already.
[Follow the instructions for your platform on the Bazel website.](https://docs.bazel.build/versions/master/install.html)

You also need to install Git, if you don't have it already.
[Follow the instructions for your platform on the Git website.](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git)

Once you've installed Bazel and Git, open a Terminal and clone the Private Join
and Compute repository into a local folder:

```shell
git clone https://github.com/ruidazeng/upsi-new.git
```

Navigate into the `upsi-new` folder you just created, and build
the Updatable Private Set Intersection library and dependencies using Bazel:

```bash
cd upsi-new
bazel build //upsi:all
```

Before running the protocol, first run the `setup` binary to generate encryption keys for the parties.

## Threshold Paillier
Two party threshold Paillier is in `upsi/crypto/threshold_paillier.h`.

To run the associated tests:
```bash
bazel test //upsi/crypto:threshold_paillier_test
```
It will take around two minutes.

There are only four functions of note:
 1. `GenerateThresholdPaillierKeys` generates two keys, one for each party.
 2. `Encrypt` encrypts a message using either party's key
 3. `PartialDecrypt` takes a ciphertext and partially decrypts it with one party's key.
 4. `Decrypt` takes a ciphertext and the other party's partial decryption and recovers the message.
Essentially of the elements involved are `BigNum`s (e.g., message, ciphertext, key components).

To see how one would use these functions, check the tests in `threshold_paillier_test.cc`.
