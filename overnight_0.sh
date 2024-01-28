#!/bin/bash

echo "2^20 - 2^4"

./bazel-bin/upsi/addition/setup --days=2 --start_size=1048543 --daily_size=16 --noexpected

./network_setup.sh off &> /dev/null
echo "./bazel-bin/upsi/addition/run --party=0 --days=2 --daily_size= --func=SUM"
echo "LAN"
./bazel-bin/upsi/addition/run --party=0 --days=2 --func=SUM

./network_setup.sh off
./network_setup.sh on 40 200
echo "200Mbps"
./bazel-bin/upsi/addition/run --party=0 --days=2 --func=SUM

./network_setup.sh off
./network_setup.sh on 40 50
echo "50Mbps"
./bazel-bin/upsi/addition/run --party=0 --days=2 --func=SUM

./network_setup.sh off
./network_setup.sh on 40 5
echo "5Mbps"
./bazel-bin/upsi/addition/run --party=0 --days=2 --func=SUM

echo ""
echo ""
echo "2^22 - 2^4"

./bazel-bin/upsi/addition/setup --days=2 --start_size=4194175 --daily_size=16 --noexpected

echo "LAN"
./network_setup.sh off
./bazel-bin/upsi/addition/run --party=0 --days=2 --func=SUM

./network_setup.sh off
./network_setup.sh on 40 200
echo "200Mbps"
./bazel-bin/upsi/addition/run --party=0 --days=2 --func=SUM

./network_setup.sh off
./network_setup.sh on 40 50
echo "50Mbps"
./bazel-bin/upsi/addition/run --party=0 --days=2 --func=SUM

./network_setup.sh off
./network_setup.sh on 40 5
echo "5Mbps"
./bazel-bin/upsi/addition/run --party=0 --days=2 --func=SUM

echo ""
echo ""
echo "2^20 - 2^6"

./bazel-bin/upsi/addition/setup --days=2 --start_size=1048447 --daily_size=64 --noexpected

echo "LAN"
./network_setup.sh off
./bazel-bin/upsi/addition/run --party=0 --days=2 --func=SUM

./network_setup.sh off
./network_setup.sh on 40 200
echo "200Mbps"
./bazel-bin/upsi/addition/run --party=0 --days=2 --func=SUM

./network_setup.sh off
./network_setup.sh on 40 50
echo "50Mbps"
./bazel-bin/upsi/addition/run --party=0 --days=2 --func=SUM

./network_setup.sh off
./network_setup.sh on 40 5
echo "5Mbps"
./bazel-bin/upsi/addition/run --party=0 --days=2 --func=SUM

echo ""
echo ""
echo "2^22 - 2^6"

./bazel-bin/upsi/addition/setup --days=2 --start_size=4194175 --daily_size=64 --noexpected

echo "LAN"
./network_setup.sh off
./bazel-bin/upsi/addition/run --party=0 --days=2 --func=SUM

./network_setup.sh off
./network_setup.sh on 40 200
echo "200Mbps"
./bazel-bin/upsi/addition/run --party=0 --days=2 --func=SUM

./network_setup.sh off
./network_setup.sh on 40 50
echo "50Mbps"
./bazel-bin/upsi/addition/run --party=0 --days=2 --func=SUM

./network_setup.sh off
./network_setup.sh on 40 5
echo "5Mbps"
./bazel-bin/upsi/addition/run --party=0 --days=2 --func=SUM

echo ""
echo ""
echo "2^20 - 2^8"

./bazel-bin/upsi/addition/setup --days=2 --start_size=1048063 --daily_size=256 --noexpected

echo "LAN"
./network_setup.sh off
./bazel-bin/upsi/addition/run --party=0 --days=2 --func=SUM

./network_setup.sh off
./network_setup.sh on 40 200
echo "200Mbps"
./bazel-bin/upsi/addition/run --party=0 --days=2 --func=SUM

./network_setup.sh off
./network_setup.sh on 40 50
echo "50Mbps"
./bazel-bin/upsi/addition/run --party=0 --days=2 --func=SUM

./network_setup.sh off
./network_setup.sh on 40 5
echo "5Mbps"
./bazel-bin/upsi/addition/run --party=0 --days=2 --func=SUM

echo ""
echo ""

echo "2^22 - 2^8"

./bazel-bin/upsi/addition/setup --days=2 --start_size=4193791 --daily_size=256 --noexpected

echo "LAN"
./network_setup.sh off
./bazel-bin/upsi/addition/run --party=0 --days=2 --func=SUM

./network_setup.sh off
./network_setup.sh on 40 200
echo "200Mbps"
./bazel-bin/upsi/addition/run --party=0 --days=2 --func=SUM

./network_setup.sh off
./network_setup.sh on 40 50
echo "50Mbps"
./bazel-bin/upsi/addition/run --party=0 --days=2 --func=SUM

./network_setup.sh off
./network_setup.sh on 40 5
echo "5Mbps"
./bazel-bin/upsi/addition/run --party=0 --days=2 --func=SUM