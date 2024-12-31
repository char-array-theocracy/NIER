#!/usr/bin/env bash
set -euo pipefail

USER_HOME="/home/$USER"
TEMPLATE_CONFIG="$USER_HOME/NIER/config/mosquitto.conf.def"
ACTUAL_CONFIG="$USER_HOME/NIER/config/mosquitto.conf"

if [[ -f "$TEMPLATE_CONFIG" ]]; then
    sed "s|0___USER___0|$USER|g" "$TEMPLATE_CONFIG" > "$ACTUAL_CONFIG"
    echo "Generated config file at $ACTUAL_CONFIG"
else
    echo "Error: Template config file not found at $TEMPLATE_CONFIG"
    exit 1
fi

if [[ -f "$ACTUAL_CONFIG" ]]; then
    echo "Starting Mosquitto..."
    mosquitto -c "$ACTUAL_CONFIG" -v &
else
    echo "Error: Mosquitto config file not found at $ACTUAL_CONFIG"
    exit 1
fi

