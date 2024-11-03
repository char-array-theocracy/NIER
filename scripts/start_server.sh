#!/bin/bash

TEMPLATE_CONFIG="/home/$USER/NIER/config/lighttpd.conf.def"
ACTUAL_CONFIG="/home/$USER/NIER/config/lighttpd.conf"

# Replace placeholder with user name
sed "s|0___USER___0|$USER|g" "$TEMPLATE_CONFIG" > "$ACTUAL_CONFIG"

# Check if all dynamic fastcgi programs are built if not build them.
SRC_DIR="/home/$USER/NIER/src/RASPB-NIER/quick-apps"
DEST_DIR="/home/$USER/NIER/assets/dynamic"
mkdir -p $DEST_DIR

# Compile each .c file in the source directory
for c_file in "$SRC_DIR"/*.c; do
    base_name=$(basename "$c_file" .c)
    
    output_file="$DEST_DIR/$base_name.fcgi"

    gcc "$c_file" -o "$output_file" -lfcgi

    if [ $? -eq 0 ]; then
        echo "Compiled $c_file to $output_file successfully."
    else
        echo "Failed to compile $c_file."
    fi
done

# Run lighthttpd

sudo lighttpd -D -f "/home/$USER/NIER/config/lighttpd.conf"
