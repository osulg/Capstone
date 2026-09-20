#!/bin/bash

TARGET="$HOME/guardfs_benign_dataset"
mkdir -p "$TARGET"

echo "normal document" > "$TARGET/original.txt"

cp "$TARGET/original.txt" "$TARGET/copy.txt"

mv "$TARGET/copy.txt" "$TARGET/renamed.txt"

cat "$TARGET/original.txt" > /dev/null
cat "$TARGET/renamed.txt" > /dev/null

rm -f "$TARGET/original.txt"
rm -f "$TARGET/renamed.txt"

echo "benign shell workload complete"
