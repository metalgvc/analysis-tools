#!/bin/bash

if [[ -z $1 ]]; then
  echo "Usage: $0 <magic number>"
  echo "example: $0 \"ffd8ffe0\""
  exit 1
fi

echo -n "$1" | xxd -r -p | file - | awk -F: '{ gsub(/^ +| +$/, "", $2); print $2 }'
