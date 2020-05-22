#!/bin/bash -eu

source /build-common.sh

BINARY_NAME="id"
COMPILE_IN_DIRECTORY="cmd/id"

# TODO: one deployerspec is done, we can stop overriding this from base image
function packageLambdaFunction {
	if [ ! -z ${FASTBUILD+x} ]; then return; fi

	cd rel/
	cp "${BINARY_NAME}_linux-amd64" "${BINARY_NAME}"
	rm -f lambdafunc.zip
	zip lambdafunc.zip "${BINARY_NAME}"
	rm "${BINARY_NAME}"
}

standardBuildProcess

buildstep packageLambdaFunction
