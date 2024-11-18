#!/usr/bin/env bash
# Error check
set -euo pipefail

USER_HOME="/home/$USER"
TEMPLATE_CONFIG1="$USER_HOME/NIER/config/lighttpd.conf.def"
TEMPLATE_CONFIG2="$USER_HOME/NIER/config/mosquitto.conf.def"
ACTUAL_CONFIG1="$USER_HOME/NIER/config/lighttpd.conf"
ACTUAL_CONFIG2="$USER_HOME/NIER/config/mosquitto.conf"
BACKEND_SRC="$USER_HOME/NIER/src/RASPB-NIER"
BACKEND_OUT="$USER_HOME/NIER/build/backend"

mkdir -p "$(dirname "$BACKEND_OUT")"

# Replace placeholder with user name and save to actual config
if [[ -f "$TEMPLATE_CONFIG1" ]]; then
    sed "s|0___USER___0|$USER|g" "$TEMPLATE_CONFIG1" > "$ACTUAL_CONFIG1"
    echo "Generated config file at $ACTUAL_CONFIG1"
else
    echo "Error: Template config file not found at $TEMPLATE_CONFIG1"
    exit 1
fi

if [[ -f "$TEMPLATE_CONFIG2" ]]; then
    sed "s|0___USER___0|$USER|g" "$TEMPLATE_CONFIG2" > "$ACTUAL_CONFIG2"
    echo "Generated config file at $ACTUAL_CONFIG2"
else
    echo "Error: Template config file not found at $TEMPLATE_CONFIG2"
    exit 1
fi

# Run mosquitto
if [[ -f "$ACTUAL_CONFIG2" ]]; then
    echo "Starting mosquitto..."
    mosquitto -c "$ACTUAL_CONFIG2" -v &
else
    echo "Error: mosquitto config file not found at $ACTUAL_CONFIG2"
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
if [[ -f "$ACTUAL_CONFIG1" ]]; then
    echo "Starting lighttpd..."
    sudo lighttpd -D -f "$ACTUAL_CONFIG1"
else
    echo "Error: lighttpd config file not found at $ACTUAL_CONFIG1"
    exit 1
fi

