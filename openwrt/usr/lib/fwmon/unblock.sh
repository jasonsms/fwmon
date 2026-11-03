#!/bin/sh
# Remove a source IP from the nftables set fwmon_block.
IP="$1"
[ -n "$IP" ] || exit 1
nft delete element inet fwmon fwmon_block "{ $IP }" 2>/dev/null || true
logger -t fwmon "unblocked $IP"
echo "unblocked $IP"
