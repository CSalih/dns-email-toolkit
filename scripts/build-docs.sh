#!/usr/bin/env bash

set -e

cargo doc --bins --no-deps
echo "<meta http-equiv=refresh content=0;url=det>" > target/doc/index.html

rm -rf docs/*
cp -r target/doc/* docs/
