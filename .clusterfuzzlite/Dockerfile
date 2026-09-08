FROM gcr.io/oss-fuzz-base/base-builder-python

COPY . $SRC/agent-manifest
COPY .clusterfuzzlite/build.sh $SRC/build.sh
WORKDIR $SRC/agent-manifest
