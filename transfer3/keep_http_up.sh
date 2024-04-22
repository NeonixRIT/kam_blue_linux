#!/bin/bash

while true; do
    # Check if the sshd service is active
    if ! systemctl is-active --quiet apache2; then
        echo "apache2 service is not active. Attempting to start apache2..."
        systemctl start apache2
        if systemctl is-active --quiet apache2; then
            echo "apache2 service has been successfully started."
        else
            echo "Failed to start apache2 service."
        fi
    fi
    sleep 1
done
