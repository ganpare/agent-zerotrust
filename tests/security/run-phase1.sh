#!/usr/bin/env bash
# Phase 1 acceptance tests (local portion) — run on the protected host.
#
# Validates the local portion of docs/issues/001-auditable-ssh-access.md:
#   SR2  session commands appear in Tetragon with full parent ancestry
#   T2   a secret read by the agent is captured in the evidence
#   T4   an outbound connect by the agent is captured in the evidence
#   T6   the agent cannot read or delete the evidence (SR3)
#   T5   the direct-SSH bypass block is active (host side; full test needs
#        a second tailnet device — see the runbook)
#
# Prereqs: warpgate + tetragon containers running; the muse client key and
# the evidence-collector key in deploy/warpgate/state/.
# The T5 check needs root: run with sudo, or it is skipped.

set -u
REPO=$(cd "$(dirname "$0")/../.." && pwd)
KEY="$REPO/deploy/warpgate/state/muse-client-key"
COLKEY="$REPO/deploy/warpgate/state/evidence-collector-key"
TS_IP=<PROTECTED_HOST_IP>
SSH_OPTS=(-F none -i "$KEY" -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null)
TARGET="muse:<PROTECTED_HOST>-local@$TS_IP"
EVENTS_DIR="$REPO/deploy/tetragon/state/events"
MON_IP=<MONITORING_HOST_IP>   # <MONITORING_HOST> (monitoring host, exempted from the block)

PASS=0; FAIL=0
ok()  { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

events() { ls -t "$EVENTS_DIR"/*.json 2>/dev/null | head -2; }

echo "== SR2: session commands appear in Tetragon with parent ancestry =="
MARKER="CORR-$(date +%s)"
ssh "${SSH_OPTS[@]}" "$TARGET" "echo $MARKER" >/dev/null 2>&1
sleep 2
if grep -h -F "$MARKER" $(events) 2>/dev/null | grep process_exec | grep '"uid":1001' | grep -q '"binary":"/bin/bash"'; then
    ok "exec event captured for the session command"
    if grep -h -F "$MARKER" $(events) 2>/dev/null | grep process_exec | grep '"uid":1001' | head -1 | grep -q '"binary":"/usr/sbin/sshd"'; then
        ok "parent ancestry: session bash under sshd (warpgate session)"
    else
        bad "parent ancestry missing (expected sshd parent)"
    fi
else
    bad "no exec event for the session command"
fi

echo "== T2: secret read by the agent is captured =="
BEFORE=$(grep -h "canary-secret.txt" $(events) 2>/dev/null | grep -c process_kprobe || true)
ssh "${SSH_OPTS[@]}" "$TARGET" "cat /home/ai-muse/canary-secret.txt >/dev/null" 2>&1
sleep 2
AFTER=$(grep -h "canary-secret.txt" $(events) 2>/dev/null | grep -c process_kprobe || true)
if [ "${AFTER:-0}" -gt "${BEFORE:-0}" ]; then
    ok "canary read captured by the sensitive-file policy"
else
    bad "canary read not found in evidence"
fi

echo "== T4: outbound connect by the agent is captured =="
MARKER2="NET-$(date +%s)"
ssh "${SSH_OPTS[@]}" "$TARGET" "curl -s --max-time 3 http://93.184.216.34 -o /dev/null; echo $MARKER2" >/dev/null 2>&1
sleep 2
if grep -h "93.184.216.34" $(events) 2>/dev/null | grep process_kprobe | grep -q '"binary":"/usr/bin/curl"'; then
    ok "outbound connect captured by the connect policy"
else
    bad "outbound connect not found in evidence"
fi

echo "== T6 / SR3: agent cannot read or delete the evidence =="
if ssh "${SSH_OPTS[@]}" "$TARGET" "cat $REPO/deploy/warpgate/state/db/db.sqlite3" 2>&1 | grep -q "Permission denied"; then
    ok "warpgate DB unreadable by the agent"
else
    bad "agent could read the warpgate DB"
fi
if ssh "${SSH_OPTS[@]}" "$TARGET" "rm $REPO/deploy/tetragon/state/events/tetragon.json" 2>&1 | grep -q "Permission denied"; then
    ok "tetragon evidence undeletable by the agent"
else
    bad "agent could delete tetragon evidence"
fi

echo "== Evidence collector: read-only SFTP =="
if printf 'get /mnt/ssd2tb/projects/Zero-trust/deploy/tetragon/state/events/tetragon.json /tmp/azt-col-test.json\n' \
    | sftp -F none -i "$COLKEY" -o StrictHostKeyChecking=no -b - evidence-collector@127.0.0.1 >/dev/null 2>&1; then
    ok "collector can pull evidence (read)"
else
    bad "collector could not read evidence"
fi
if printf 'put /etc/hostname /tmp/azt-col-up-test\n' \
    | sftp -F none -i "$COLKEY" -o StrictHostKeyChecking=no -b - evidence-collector@127.0.0.1 >/dev/null 2>&1; then
    bad "collector write was not denied (must be read-only)"
else
    ok "collector write denied (read-only enforced)"
fi

echo "== T5 (host side): direct-SSH bypass block over Tailscale =="
if [ "$(id -u)" -eq 0 ]; then
    if iptables -C INPUT -i tailscale0 -p tcp --dport 22 ! -s "$MON_IP" -j DROP >/dev/null 2>&1; then
        ok "nftables/iptables rule active (TS :22 blocked except $MON_IP)"
    else
        bad "bypass rule not present"
    fi
    echo "  NOTE: full T5 validation requires a connection attempt from a"
    echo "        second tailnet device: ssh -p 22 $TS_IP must FAIL, and"
    echo "        ssh -p 2222 must reach warpgate."
elif command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
    if sudo iptables -C INPUT -i tailscale0 -p tcp --dport 22 ! -s "$MON_IP" -j DROP >/dev/null 2>&1; then
        ok "nftables/iptables rule active (TS :22 blocked except $MON_IP)"
        echo "  NOTE: full T5 validation needs a second tailnet device."
    else
        bad "bypass rule not present"
    fi
else
    echo "  SKIP: needs root to check iptables (run with sudo, or verify"
    echo "        with: iptables -C INPUT -i tailscale0 -p tcp --dport 22 ! -s $MON_IP -j DROP)"
fi

echo
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
