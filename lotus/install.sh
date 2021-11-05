#!/bin/sh


# env for build
export RUSTFLAGS="-C target-cpu=native -g" 
export CGO_CFLAGS="-D__BLST_PORTABLE__"
export FFI_BUILD_FROM_SOURCE=1

echo "make "$1
case $1 in
    "debug")
        cp -f scripts/bootstrappers.pi build/bootstrap/devnet.pi
        cp -f scripts/devnet.car build/genesis/devnet.car
        make debug
        git checkout build
    ;;
    "hlm")
        cp -f scripts/bootstrappers.pi build/bootstrap/devnet.pi
        cp -f scripts/devnet-hlm.car build/genesis/devnet.car
        make hlm
        git checkout build
    ;;
    "calibration")
        make calibnet
    ;;
    *)
        make $1
    ;;
esac

