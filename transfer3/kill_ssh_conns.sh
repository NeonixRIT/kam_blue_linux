#!/bin/bash

while true; do
    ps aux | grep 'sshd:' | grep -v 'grep' | awk '{print $1, $2}' | while read user pid; do
        if [[ "$user" != "root" && "$user" != "sshd" && "$user" != "Grey_Team" ]]; then
            echo "Killing SSH session for user $user with PID $pid."
            kill -9 $pid
        fi
    done
    sleep 1
done
