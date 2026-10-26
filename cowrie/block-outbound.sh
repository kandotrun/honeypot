#!/bin/sh
# Outbound policy for the honeypot container networks (decided
# 2026-10-26, extended to OpenCanary the same day):
# - Allow NEW tcp/80 and tcp/443 toward PUBLIC destinations only, so
#   attacker-triggered downloads (malware samples) actually arrive.
# - Drop NEW traffic to private / CGNAT (tailnet) / loopback /
#   link-local / reserved ranges even on 80/443.
# - Drop all other NEW outbound (other ports, UDP, ...).
# - Host-local destinations never traverse FORWARD, so a
#   source-matched INPUT drop guards them separately.
# Replies to inbound honeypot sessions are conntrack ESTABLISHED and
# are not matched by these NEW rules.
# Idempotent: safe to run at every boot via cowrie-fw.service.
SUBNETS="172.30.0.0/24 172.31.0.0/24"
CT="-m conntrack --ctstate NEW"

for SUBNET in $SUBNETS; do
  # Remove the first-generation blanket rule if it is still around.
  OLD="-s $SUBNET ! -d $SUBNET $CT -j DROP"
  while iptables -C DOCKER-USER $OLD 2>/dev/null; do
    iptables -D DOCKER-USER $OLD
  done

  # Desired rules, top to bottom. Insert missing ones at position 1
  # in reverse order so the final sequence matches this list.
  RULES="
-s $SUBNET -d 10.0.0.0/8 $CT -j DROP
-s $SUBNET -d 172.16.0.0/12 $CT -j DROP
-s $SUBNET -d 192.168.0.0/16 $CT -j DROP
-s $SUBNET -d 100.64.0.0/10 $CT -j DROP
-s $SUBNET -d 127.0.0.0/8 $CT -j DROP
-s $SUBNET -d 169.254.0.0/16 $CT -j DROP
-s $SUBNET -d 192.0.0.0/24 $CT -j DROP
-s $SUBNET -d 198.18.0.0/15 $CT -j DROP
-s $SUBNET -d 224.0.0.0/4 $CT -j DROP
-s $SUBNET -d 240.0.0.0/4 $CT -j DROP
-s $SUBNET -p tcp --dport 80 $CT -j ACCEPT
-s $SUBNET -p tcp --dport 443 $CT -j ACCEPT
-s $SUBNET $CT -j DROP
"
  echo "$RULES" | grep -v '^$' | tac | while IFS= read -r rule; do
    if iptables -C DOCKER-USER $rule 2>/dev/null; then
      echo "present: $rule"
    else
      iptables -I DOCKER-USER 1 $rule
      echo "inserted: $rule"
    fi
  done

  INPUT_RULE="-s $SUBNET $CT -j DROP"
  if iptables -C INPUT $INPUT_RULE 2>/dev/null; then
    echo "present: INPUT $INPUT_RULE"
  else
    iptables -I INPUT 1 $INPUT_RULE
    echo "inserted: INPUT $INPUT_RULE"
  fi
done

iptables -L DOCKER-USER -n | head -35 || true
exit 0
