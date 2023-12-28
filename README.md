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

Make sure the directory has a folder named `data` which holds all the generated dummy data.

Arguments we can use to specify the properties of the data generated includes `days`, `p0_size`, `p1_size`, `shared_size`, `per_day`, and `max_value`.

(Note: the number of elements in the intersection is randomly generated regardless of `shared_size`).

```bash
mkdir data
./bazel-bin/upsi/setup
```

To run the protocol, have two instances (terminals) open. First we initialize Party 1 using:

```bash
./bazel-bin/upsi/run --party=1 --func=CA
```

Then we initialize Party 0 using:
```bash
./bazel-bin/upsi/run --party=0 --func=CA
```

Arguments we can use to specify the properties of the two parties includes `party`, `port`, `dir`, `func`, `days`.

`func` will specify the desired protocol functionality:

`CA`: cardinality

`SUM`: sum

`SS`: secret sharing

## Setting Up on Google Cloud

> [!NOTE] 
> There is already a VM setup in the UPSI project on Google Cloud called `upsi-1` that has cloned the repository and
> installed bazel. Given the `id_upsi` ssh key, you should be able to connect and directly run the project there. 
> 
> The following instructions are for setting up a new machine.

First, you will need to setup an ssh key. Ideally you will use the `id_upsi` key that we all already have. To add a key, 
go to the VM instance on the Google Cloud console, click "EDIT" in the top bar, scroll down to the **SSH Keys** section,
and add the contents of `id_upsi.pub` to a new key. 

You should then be able to ssh into the machine however you'd like with the username `upsi` (assuming you've used the
`id_upsi` key — other keys may have another username). The IP address can be found on the VM page under **Network
interfaces** as _External IP address_.

To clone the repository the machine will need `git` installed and an authorized key to access GitHub. To install `git`,
you should be able to run 
```bash
sudo apt-get install git
```
To setup a new key, you can create one by running the following:
```bash
ssh-keygen -t ed25519 -C "<your@email>"
```
and adding the contents of the `.pub` file to your GitHub account (under *Settings > SSH and GPG keys*). `upsi-1` has
`id_github` as its key for connecting to GitHub using Max's account.

Before you clone or pull the repository, you may need to add the ssh key to the ssh agent. This can be done by running
the following commands:
```bash
eval $(ssh-agent)
ssh-add ~/.ssh/id_github
```

To install Bazel, you can run the commands in [Using Bazel's apt repository](https://bazel.build/install/ubuntu).:
```bash
sudo apt install apt-transport-https curl gnupg -y
curl -fsSL https://bazel.build/bazel-release.pub.gpg | gpg --dearmor >bazel-archive-keyring.gpg
sudo mv bazel-archive-keyring.gpg /usr/share/keyrings
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/bazel-archive-keyring.gpg] https://storage.googleapis.com/bazel-apt stable jdk1.8" | sudo tee /etc/apt/sources.list.d/bazel.list

sudo apt update && sudo apt install bazel-6.4.0
```
Note that since our project is pinned to Bazel 6.4.0 you need to install that version specifically.

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
