#!/bin/sh

export CGO_CFLAGS_ALLOW="-D__BLST_PORTABLE__"
export CGO_CFLAGS="-D__BLST_PORTABLE__"

export LOTUS_PATH=~/.lotusDevnet
export LOTUS_MINER_PATH=~/.lotusminerDevnet
export LOTUS_SKIP_GENESIS_CHECK=_yes_

echo $CGO_CFLAGS_ALLOW
echo $CGO_CFLAGS
echo $LOTUS_PATH
echo $LOTUS_MINER_PATH
echo $LOTUS_SKIP_GENESIS_CHECK
