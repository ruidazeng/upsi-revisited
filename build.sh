#!/bin/bash

# setup build dependencies
sudo apt-get install python-pip -y
sudo apt-get install python3-distutils -y

# setup bazel
sudo apt install apt-transport-https curl gnupg -y
curl -fsSL https://bazel.build/bazel-release.pub.gpg | gpg --dearmor >bazel-archive-keyring.gpg
sudo mv bazel-archive-keyring.gpg /usr/share/keyrings
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/bazel-archive-keyring.gpg] https://storage.googleapis.com/bazel-apt stable jdk1.8" | sudo tee /etc/apt/sources.list.d/bazel.list

sudo apt update && sudo apt install bazel-6.4.0 -y

# make sure these are in /usr/bin/
sudo update-alternatives --install /usr/bin/bazel bazel /usr/bin/bazel-6.4.0 10
sudo update-alternatives --install /usr/bin/tc tc /usr/sbin/tc 10

# and build the project
bazel build //upsi:all
