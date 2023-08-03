#!/usr/bin/env bash

TOOL=vault-plugin-secrets-engine-buddy

# This script builds the application from the source for the provided platform.

set -e

GO_CMD=${GO_CMD:-go}

# Get the parent directory of the script location.
SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ] ; do SOURCE="$(readlink "$SOURCE")"; done
DIR="$( cd -P "$( dirname "$SOURCE" )/.." && pwd )"

# Change into that directory
cd "$DIR"

# Set the build tags
BUILD_TAGS="${BUILD_TAGS}:-${TOOL}"

# Get the commit
GIT_COMMIT="$(git rev-parse HEAD)"
GIT_DIRTY="$(test -n "`git status --porcelain`" && echo "+CHANGES" || true)"

GOPATH=${GOPATH:-$(go env GOPATH)}
case $(uname) in
    CYGWIN*)
        GOPATH="$(cygpath $GOPATH)"
        ;;
esac

# Delete the old directory
echo "Removing old directory..."
rm -f bin/*
rm -rf pkg/*
mkdir -p bin/

# Build!
echo "Building..."
${GO_CMD} build \
    -gcflags "${GCFLAGS}" \
    -ldflags "-X github.com/buddy/${TOOL}/version.GitCommit='${GIT_COMMIT}${GIT_DIRTY}'" \
    -o "bin/${TOOL}" \
    -tags "${BUILD_TAGS}" \
    "${DIR}/cmd/${TOOL}"

# Move all compiled things to the $GOPATH/bin
OLDIFS=$IFS
IFS=: MAIN_GOPATH=($GOPATH)
IFS=$OLDIFS

rm -f ${MAIN_GOPATH}/bin/${TOOL}
cp bin/${TOOL} ${MAIN_GOPATH}/bin/

# Done!
echo
echo "Results:"
ls -hl bin/
