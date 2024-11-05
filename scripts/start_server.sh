#!/usr/bin/env bash
# Error check
set -euo pipefail

USER_HOME="/home/$USER"
TEMPLATE_CONFIG="$USER_HOME/NIER/config/lighttpd.conf.def"
ACTUAL_CONFIG="$USER_HOME/NIER/config/lighttpd.conf"
BACKEND_SRC="$USER_HOME/NIER/src/RASPB-NIER"
BACKEND_OUT="$USER_HOME/NIER/build/backend"

mkdir -p "$(dirname "$BACKEND_OUT")"

# Replace placeholder with user name and save to actual config
if [[ -f "$TEMPLATE_CONFIG" ]]; then
    sed "s|0___USER___0|$USER|g" "$TEMPLATE_CONFIG" > "$ACTUAL_CONFIG"
    echo "Generated config file at $ACTUAL_CONFIG"
else
    echo "Error: Template config file not found at $TEMPLATE_CONFIG"
    exit 1
fi

# Compile backend
echo "Building backend..."
gcc "$BACKEND_SRC/main.c" "$BACKEND_SRC/cJSON.c" "$BACKEND_SRC/responses.c" -o "$BACKEND_OUT" -lpthread -lfcgi
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


