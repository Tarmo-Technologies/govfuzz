#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Clone the comparison subset: one representative project per language, kept on
# disk (unlike the streamed sweep) because every tool under comparison has to
# read the SAME tree for the numbers to mean anything.
set -e
DEST="${DEST:-/home/ubuntu/govfuzz-compare-set}"
mkdir -p "$DEST"
clone() { # lane url
    name="$(basename "$2" .git)"
    dir="$DEST/$1/$name"
    [ -d "$dir/.git" ] && return 0
    mkdir -p "$DEST/$1"
    git clone --depth 1 --quiet --no-tags "$2" "$dir" || echo "clone failed: $2"
}
clone c      https://github.com/akheron/jansson.git
clone c      https://github.com/DaveGamble/cJSON.git
clone cpp    https://github.com/google/leveldb.git
clone cpp    https://github.com/leethomason/tinyxml2.git
clone rust   https://github.com/sharkdp/fd.git
clone go     https://github.com/FiloSottile/mkcert.git
clone python https://github.com/psf/requests.git
clone java   https://github.com/google/gson.git
clone php    https://github.com/Seldaek/monolog.git
clone ruby   https://github.com/tmuxinator/tmuxinator.git
clone perl   https://github.com/major/MySQLTuner-perl.git
clone lua    https://github.com/kikito/inspect.lua.git
echo "compare set in $DEST"
du -sh "$DEST"
