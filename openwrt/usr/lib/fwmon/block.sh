#!/bin/sh
# Optional auto-block helper: add a source IP to the nftables set fwmon_block.
# Only acts when auto_block is enabled in /etc/config/fwmon.
IP="$1"
[ -n "$IP" ] || exit 1
enabled="$(uci -q get fwmon.main.auto_block)"
[ "$enabled" = "1" ] || { echo "auto-block disabled"; exit 0; }
nft add element inet fwmon fwmon_block "{ $IP }" 2>/dev/null || true
logger -t fwmon "blocked $IP"
echo "blocked $IP"
