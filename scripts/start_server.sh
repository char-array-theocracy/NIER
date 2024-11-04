#!/usr/bin/env bash
# Error check
set -euo pipefail

USER_HOME="/home/$USER"
TEMPLATE_CONFIG="$USER_HOME/NIER/config/lighttpd.conf.def"
ACTUAL_CONFIG="$USER_HOME/NIER/config/lighttpd.conf"
SRC_DIR="$USER_HOME/NIER/src/RASPB-NIER/quick-apps"
DEST_DIR="$USER_HOME/NIER/assets/dynamic"
BACKEND_SRC="$USER_HOME/NIER/src/RASPB-NIER/deamon-backend/main.c"
BACKEND_OUT="$USER_HOME/NIER/build/backend"

mkdir -p "$DEST_DIR"
mkdir -p "$(dirname "$BACKEND_OUT")"

# Replace placeholder with user name and save to actual config
if [[ -f "$TEMPLATE_CONFIG" ]]; then
    sed "s|0___USER___0|$USER|g" "$TEMPLATE_CONFIG" > "$ACTUAL_CONFIG"
    echo "Generated config file at $ACTUAL_CONFIG"
else
    echo "Error: Template config file not found at $TEMPLATE_CONFIG"
    exit 1
fi

# Compile each FCGI file in the source directory
if compgen -G "$SRC_DIR"/*.c > /dev/null; then
    for c_file in "$SRC_DIR"/*.c; do
        base_name=$(basename "$c_file" .c)
        output_file="$DEST_DIR/$base_name.fcgi"

        gcc "$c_file" -o "$output_file" -lfcgi
        echo "Compiled $c_file to $output_file successfully."
    done
else
    echo "No .c files found in $SRC_DIR"
fi

# Compile backend
echo "Building backend..."
gcc "$BACKEND_SRC" -o "$BACKEND_OUT" -pthread
echo "Backend built at $BACKEND_OUT"

# Run backend in the background
"$BACKEND_OUT" &
echo "Backend is running in the background."

# Run lighttpd
if [[ -f "$ACTUAL_CONFIG" ]]; then
    echo "Starting lighttpd..."
    sudo lighttpd -D -f "$ACTUAL_CONFIG"
else
    echo "Error: lighttpd config file not found at $ACTUAL_CONFIG"
    exit 1
fi


