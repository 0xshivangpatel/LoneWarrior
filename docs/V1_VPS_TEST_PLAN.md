# LoneWarrior V1 VPS Test Plan (Safe, Reversible)

This runbook is designed for a single Linux VPS running LoneWarrior as root (systemd service), with **iptables** available.

## Preconditions
- Install and start the agent (`lw status` works)
- You have console access in case you lock yourself out
- Optional but recommended: run inside a *throwaway* VPS snapshot

## Test 1 — Phase 0: builtin blacklist is enforced
- **Setup**: add your workstation IP temporarily to the blacklist file:
  - Edit `lonewarrior/threat_intel/blacklist_ips.txt` and add:
    - `<YOUR_IP>`
- **Run**: restart the service:
  - `sudo systemctl restart lonewarrior`
- **Expected**:
  - Your IP gets blocked (cannot connect)
  - Rollback path: remove the IP from the file, restart service, or run `iptables-restore` from snapshot if needed

## Test 2 — SSH brute force triggers threat-intel detection → IP block
- **Setup**: from a separate host, attempt failed SSH logins:
  - `for i in $(seq 1 10); do ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no baduser@<VPS_IP>; done`
- **Expected**:
  - `lw detections` shows a `threat_intel_hit`
  - `lw actions` shows an `ip_block` for the attacker IP

## Test 3 — Containment mode engages at lockdown threshold
- **Setup**: create a high confidence invariant (safe version):
  - Run a process event that matches the invariant rule: web parent spawning shell is hard to simulate safely; instead, temporarily lower `confidence.lockdown` to `50` in `/etc/lonewarrior/config.yaml` (or your config) and restart.
- **Run**:
  - Generate any detection with confidence ≥ lockdown (e.g., trigger an invariant, or manually insert a detection via test script)
- **Expected**:
  - `lw status` shows containment active
  - Outbound becomes blocked except whitelist (if configured)
  - New SSH logins are blocked if `containment.pause_ssh_logins: true`

## Test 4 — Containment expiry restores networking (snapshot rollback)
- **Setup**: set `containment.default_duration: 60` (1 minute)
- **Run**: trigger containment and wait 70–90 seconds
- **Expected**:
  - Containment state clears
  - iptables rules are restored (connectivity returns)

## Test 5 — IP block TTL expires and is auto-removed
- **Setup**: set `actions.ip_block.default_ttl: 30`
- **Run**: trigger a block (via auth failures or manual contain)
- **Expected**:
  - An `ip_unblock` action appears after ~30–45 seconds

## Emergency recovery (if you lock yourself out)
- Use VPS console and run:
  - `sudo iptables-restore < /path/to/last-known-good.rules` (if you have one)
  - Or flush (last resort):
    - `sudo iptables -F`
    - `sudo iptables -X`



