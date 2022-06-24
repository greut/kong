#!/bin/sh

set -ex

FROM_VERSION=2.8.1
TO_VERSION=master
NETWORK_NAME=migration-$FROM_VERSION-$TO_VERSION

trap "echo exiting because of error" 0

gojira up -t $FROM_VERSION --network $NETWORK_NAME > upgrade-up-$FROM_VERSION.log 2>&1
gojira run -t $FROM_VERSION make dev > upgrade-make-dev-$FROM_VERSION.log 2>&1
gojira up -t $TO_VERSION --alone --network $NETWORK_NAME > upgrade-up-$TO_VERSION.log 2>&1
gojira run -t $TO_VERSION make dev > upgrade-make-dev-$TO_VERSION.log 2>&1
gojira run -t $FROM_VERSION kong migrations bootstrap
gojira run -t $TO_VERSION kong migrations up
# test old version before
# test new version migrating
gojira run -t $TO_VERSION kong migrations finish
# test new version after

trap "" 0
