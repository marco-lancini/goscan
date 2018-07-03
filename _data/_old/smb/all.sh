#!/bin/sh

# CHECK ARGS
if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Usage: $0 <IP> <PORT>"
    exit 1
fi

IP=$1
PORT=$2
echo "$IP $PORT"

for FP in `ls *.py`; do
    python $FP $IP $PORT
done