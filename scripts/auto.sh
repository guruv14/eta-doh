#!/bin/bash

SITES=("google.com" "wikipedia.org" "github.com" "reddit.com" "annauniv.edu") #sample

while true; do
    SITE=${SITES[$RANDOM % ${#SITES[@]}]}
    echo "Querying $SITE via DoH..."
    
    # curl builtin DoH
    curl --doh-url https://cloudflare-dns.com/dns-query -I "https://$SITE" > /dev/null 2>&1
    
    # Wait between 3 to 10 seconds
    SLEEP_TIME=$(( ( RANDOM % 7 )  + 3 ))
    sleep $SLEEP_TIME
done
