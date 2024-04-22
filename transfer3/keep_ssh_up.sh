#!/bin/bash

while true; do
    # Check if the sshd service is active
    if ! systemctl is-active --quiet sshd; then
        echo "sshd service is not active. Attempting to start sshd..."
        systemctl start sshd
        if systemctl is-active --quiet sshd; then
            echo "sshd service has been successfully started."
        else
            echo "Failed to start sshd service."
        fi
    fi
    sleep 1
done
