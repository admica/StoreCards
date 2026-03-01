#!/usr/bin/env bash
set -euo pipefail

APP_DIR="$(cd "$(dirname "$0")" && pwd)"
CERT_DIR="$APP_DIR/certs"

echo ""
echo "StoreCard HTTPS Setup (Tailscale)"
echo "================================="
echo ""
echo "This uses Tailscale to get trusted Let's Encrypt certificates"
echo "so HTTPS works on all your devices with no extra setup."
echo ""

# Check Tailscale is installed
if ! command -v tailscale &>/dev/null; then
  echo "Error: Tailscale is not installed."
  echo ""
  echo "Install it:"
  echo "  curl -fsSL https://tailscale.com/install.sh | sh"
  echo ""
  echo "Then log in:"
  echo "  sudo tailscale up"
  echo ""
  exit 1
fi

# Check Tailscale is connected
if ! tailscale status &>/dev/null; then
  echo "Error: Tailscale is not connected."
  echo "Run: sudo tailscale up"
  exit 1
fi

# Get the machine's Tailscale FQDN
FQDN=$(tailscale status --json | node -e "
  const data = JSON.parse(require('fs').readFileSync('/dev/stdin','utf8'));
  console.log(data.Self.DNSName.replace(/\.\$/, ''));
")

if [ -z "$FQDN" ]; then
  echo "Error: Could not determine Tailscale hostname."
  echo "Make sure Tailscale is running: tailscale status"
  exit 1
fi

echo "Tailscale hostname: $FQDN"
echo ""

# Enable HTTPS in Tailscale (requires MagicDNS)
echo "Fetching certificates from Let's Encrypt via Tailscale..."
mkdir -p "$CERT_DIR"

sudo tailscale cert \
  --cert-file "$CERT_DIR/server.crt" \
  --key-file "$CERT_DIR/server.key" \
  "$FQDN"

# Make certs readable by the current user
sudo chown "$(whoami)" "$CERT_DIR/server.crt" "$CERT_DIR/server.key"
chmod 600 "$CERT_DIR/server.key"
chmod 644 "$CERT_DIR/server.crt"

# Save the FQDN for the storecard script to display
echo "$FQDN" > "$CERT_DIR/.hostname"

echo ""
echo "Certificates saved to $CERT_DIR/"
echo ""
echo "================================================================"
echo "  Setup complete!"
echo "================================================================"
echo ""
echo "No extra device setup needed — these are real Let's Encrypt"
echo "certificates that all browsers trust automatically."
echo ""
echo "Just install Tailscale on your phone:"
echo "  iOS:     App Store → Tailscale"
echo "  Android: Play Store → Tailscale"
echo "  Sign in with the same account."
echo ""
echo "Then restart StoreCard:"
echo "  ./storecard restart"
echo ""
echo "Access it at: https://$FQDN:2223"
echo ""
echo "Note: Certificates expire after 90 days."
echo "Re-run this script to renew: ./setup-https.sh"
echo ""
