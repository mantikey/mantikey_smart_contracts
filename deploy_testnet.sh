#!/bin/bash

source .env
echo "deploying on $SEPOLIA_RPC"


forge script ./script/MantiKey.s.sol --rpc-url $SEPOLIA_RPC --broadcast --verify -vvvv --retries 4 --delay 10