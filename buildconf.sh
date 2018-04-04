#!/bin/bash

set -x
set -e

automake --add-missing
autoreconf -fvi
rm -rf autom4te*.cache

exit 0
