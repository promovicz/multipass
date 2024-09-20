#!/bin/sh

set -e

if [ -d keys ]; then
	echo "Error: this script should only run once"
	exit 1
fi

mkdir -p keys/common
chmod 700 keys
chmod 700 keys/common
dd if=/dev/random bs=16 count=1 of=keys/common/cbid-ask-1.bin
dd if=/dev/random bs=16 count=1 of=keys/common/ndef-ask-1.bin
chmod 400 keys/common/*

