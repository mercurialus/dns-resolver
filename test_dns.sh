#!/usr/bin/bash

# Function to print usage
print_usage() {
  echo "Usage: $0 [-t TYPE] domain1 [domain2 ...]"
  echo "       $0 clean"
  echo ""
  echo "Options:"
  echo "  -t TYPE   DNS query type (A, AAAA, MX, CNAME). Default is A."
  exit 1
}

# Handle 'clean' separately
if [[ "$1" == "clean" ]]; then
  echo "Running make clean..."
  make clean
  exit 0
fi

# Default query type
QTYPE="A"

# Parse flags
while getopts ":t:" opt; do
  case $opt in
    t)
      QTYPE=$(echo "$OPTARG" | tr '[:lower:]' '[:upper:]')
      ;;
    \?)
      echo "Invalid option: -$OPTARG"
      print_usage
      ;;
    :)
      echo "Option -$OPTARG requires an argument."
      print_usage
      ;;
  esac
done

shift $((OPTIND -1))

# If no domains provided
if [[ $# -eq 0 ]]; then
  echo "Error: No domain names provided."
  print_usage
fi

# Build project
echo "Running make..."
make

EXECUTABLE="bin/dns_resolver"

# Loop through each domain
for DOMAIN in "$@"; do
  echo "----------------------------------------"
  echo "Query: $QTYPE $DOMAIN"

  # Run your DNS resolver
  echo -e "\nYour Resolver Output:"
  $EXECUTABLE "$DOMAIN" --type="$QTYPE"

  # Run dig
  echo -e "\ndig Output:"
  dig "$DOMAIN" "$QTYPE" +short

  echo "----------------------------------------"
  echo ""
done
