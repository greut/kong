#!/bin/sh

function usage() {
    cat <<EOF
usage: $0 [-n] <from-version> <to-version>

 <from-version> and <to-version> need to be git versions

 Options:
   -n do not build containers, just run the tests

EOF
}

args=$(getopt n $*)
if [ $? -ne 0 ]
then
    usage
    exit 1
fi
set -- $args

while :; do
    case "$1" in
        -n)
            no_build=1
            shift
            ;;
        --)
            shift
            break
            ;;
    esac
done

if [ $# -ne 2 ]
then
    echo "Missing <from-version> or <to-version>"
    usage
    exit 1
fi

FROM_VERSION=$1
TO_VERSION=$2
NETWORK_NAME=migration-$FROM_VERSION-$TO_VERSION

set -ex

trap "echo exiting because of error" 0

FROM_PREFIX=$(gojira prefix -t $FROM_VERSION)
TO_PREFIX=$(gojira prefix -t $TO_VERSION)
UPGRADE_TEST_DIR=/kong/spec/05-upgrade
UPGRADE_TEST_FILE=upgrade-$FROM_VERSION-${TO_VERSION}_spec.lua

mkdir -p upgrade-test-log
cd upgrade-test-log

function build_containers() {
    gojira up -t $FROM_VERSION --network $NETWORK_NAME > up-$FROM_VERSION.log 2>&1
    gojira run -t $FROM_VERSION make dev > make-dev-$FROM_VERSION.log 2>&1
    gojira up -t $TO_VERSION --alone --network $NETWORK_NAME > up-$TO_VERSION.log 2>&1
    gojira run -t $TO_VERSION make dev > make-dev-$TO_VERSION.log 2>&1
}

function run_tests() {
    # Copy upgrade test from target version every time we run the
    # tests as it may have been edited during development
    docker cp ${TO_PREFIX}-kong-1:$UPGRADE_TEST_DIR/$UPGRADE_TEST_FILE /tmp
    docker cp /tmp/$UPGRADE_TEST_FILE ${FROM_PREFIX}-kong-1:/tmp
    gojira run -t $FROM_VERSION kong migrations reset --yes
    gojira run -t $FROM_VERSION kong migrations bootstrap
    gojira run -t $TO_VERSION kong migrations up
    gojira run -t $FROM_VERSION "bin/busted -v -t before /tmp/$UPGRADE_TEST_FILE"
    gojira run -t $TO_VERSION "bin/busted -v -t migrating $UPGRADE_TEST_DIR/$UPGRADE_TEST_FILE"
    gojira run -t $TO_VERSION kong migrations finish
    gojira run -t $TO_VERSION "bin/busted -v -t after $UPGRADE_TEST_DIR/$UPGRADE_TEST_FILE"
}

if [ -z "$no_build" ]
then
    build_containers
fi
run_tests

trap "" 0
