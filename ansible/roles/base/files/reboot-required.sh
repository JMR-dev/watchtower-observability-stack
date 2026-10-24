#!/usr/bin/env bash
# Writes /var/run/reboot-required when an installed update (kernel, glibc,
# systemd...) needs a reboot, which is the sentinel kured watches. AlmaLinux
# has no such file of its own; needs-restarting -r exits 1 when a reboot is
# needed.
set -euo pipefail

if needs-restarting -r >/dev/null 2>&1; then
  rm -f /var/run/reboot-required
else
  touch /var/run/reboot-required
fi
