#!/usr/bin/bash

# Check if any argument is passed
if [[ $# -eq 0 ]]; then
  DOMAIN="google.com"
else
  DOMAIN="$1"
fi

# Check if the bin directory exists
if [[ "$1" == "clean" ]]; then
  make clean
fi

# Always build the project
make

# Define the path to the executable
EXECUTABLE="bin/dns_resolver"

# Run the executable with the domain as argument
$EXECUTABLE "$DOMAIN"
