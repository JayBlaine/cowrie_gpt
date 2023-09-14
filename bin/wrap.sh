#!/bin/bash

if [ -z "$1" ]; then
  echo "Error: The first argument is missing."
  exit 1
fi

# trap ctrl-c and call ctrl_c()

function ctrl_c() {
  "$1" stop
  exit
}

trap 'ctrl_c "$1"' INT

if $1 status | grep -q "PID"
then
  $1 restart
else
  $1 start
fi

while true
        do
          if $1 status | grep -q "PID"
        then
            $1 status
            sleep 5  # Adjust this interval as needed
        else
            sleep 10
            echo "Cowrie is not running. Starting Cowrie..."
            $1 start
        fi
done
}
