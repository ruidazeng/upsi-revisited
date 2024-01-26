# UPSI Project

## Building the Project

The project build is managed by `bazel` and is set up to run on `v6.4`. To build the project, simply run the following
from the `upsi-new` directory. For addition only, run
```bash
bazel build //upsi/addition:all
```

For addition & deletion, run
```bash
bazel build //upsi/deletion:all
```

## Running the Protocol

Before running the protocol, use the `setup` binary to generate encryption keys and mock input sets. By default, the keys
will be put in `out/` and the input sets will be put in `data/`. For example, to generate input datasets with 256
elements for eight days, you would run
```bash
./bazel-bin/upsi/setup --days=8 --daily_size=256
```
If you don't want to start the protocol from the beginning, but want the parties to already have built up their
datasets, you can add `--start_size=` to specify how many elements should be in their trees (e.g., to simulate running
the protocol after 100 days where each day the parties input 64 elements, you would have `--start_size=64000`).

> [!IMPORTANT]
> If you want to run the protocol to output a secret sharing of the intersection, you will need to add `--func=SS` to
> the `setup` command. Setting up the initial trees requires encrypting elements, which for secret sharing must be
> Paillier encryption whereas all other functionalities use El Gamal (and so El Gamal is the default). If you are
> starting from day 1 (i.e., `--start_size=0`), then technically this can be ignored.

Additional options can be found by running
```bash
./bazel-bin/upsi/setup --help
```

Once you've generated the keys and data sets, you can run the protocol like so
```bash
./bazel-bin/upsi/run --party=1 --days=8 --func=CA
```
and
```bash
./bazel-bin/upsi/run --party=0 --days=8 --func=CA
```
where `--func` specifies which output functionality you want to run. The functionality options are `CA` for cardinality,
`PSI` for regular PSI, `SUM` for the cardinality and sum of associated values, and `SS` is for intersection secret share.
Again, you can use `--help` to see all options for `run`.

> [!NOTE]
> You must run `run --party=1` before `run --party=0` as it acts as the server and listens for connections on the
> specified port.

## Setting Up on Google Cloud

> [!IMPORTANT]
> If you are setting up a new VM, it needs to be set to have Debian 10 (buster) as its boot disk. Otherwise the
> build will not work.

These instructions are for setting up the project on a completely new machine on Google Cloud.

First, you will need to `ssh` onto the machine. To add a new key to a Google Cloud VM, go to the VM instance on the
Google Cloud console, click "EDIT" in the top bar, scroll down to the **SSH Keys** section, and add the contents of the
`.pub` file to a new key.

You should then be able to ssh into the machine however you'd like with the username `upsi` (assuming you've used the
`id_upsi` key — other keys may have another username). The IP address can be found on the VM page under **Network
interfaces** as _External IP address_.

Once you've `ssh`'d onto the machine you will need to clone the repository, which requies the VM to have an authorized
key to access Github. Start by installing `git`:
```bash
sudo apt-get install git -y
```
Then setup a new key on the machine:
```bash
ssh-keygen -t ed25519 -C "<your@email>"
```
and add the contents of the `.pub` file to your GitHub account (under *Settings > SSH and GPG keys*).

Before you clone or pull the repository, you may need to add the ssh key to the ssh agent. This can be done by running
the following command:
```bash
eval $(ssh-agent); ssh-add ~/.ssh/id_github
```

Once you've cloned the repository, you can download build dependencies and fully build the project by running the
`build.sh` script.
