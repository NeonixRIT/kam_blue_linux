#!/bin/bash

while true; do
    ps aux | grep -E 'bluetooth'  | grep -v 'grep' | awk '{print $1, $2, $NF}' | while read user pid; do
            echo "Killing bluetooth session for user $user with PID $pid."
            kill -9 $pid
    done
    ps aux | grep -E 'sleep'  | grep -v 'grep' | awk '{print $1, $2, $NF}' | while read user pid time; do
        if [[ "$time" =~ ^[0-9]+$ && "$time" -gt 1 ]]; then
            echo "Killing sleep session for user $user with PID $pid."
            kill -9 $pid
        fi
    done
    sleep 1
done
