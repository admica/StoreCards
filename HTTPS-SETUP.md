# StoreCard HTTPS Setup Guide

This guide walks you through setting up HTTPS for StoreCard so the PWA, service workers, and camera-based barcode scanning all work on your phone over your local network.

We use **Tailscale** — a free mesh VPN that gives your devices private, encrypted connections and real trusted HTTPS certificates with zero port forwarding or firewall config.

---

## What You're Setting Up

```
Phone (Tailscale) ──── encrypted tunnel ────> Raspberry Pi (Tailscale)
     │                                              │
     └── https://raspberrypi.xxx.ts.net:2223 ──────┘
```

Your Pi gets a hostname like `raspberrypi.your-tailnet.ts.net` with a real Let's Encrypt certificate. Every browser trusts it automatically — no warnings, no CA installs.

---

## Step 1: Create a Tailscale Account

1. Go to https://login.tailscale.com/start
2. Sign up with Google, GitHub, Microsoft, or email — whatever is easiest
3. This creates your "tailnet" (your private network). The free plan supports up to 100 devices

---

## Step 2: Install Tailscale on Your Raspberry Pi

SSH into your Pi (or open a terminal) and run:

```bash
curl -fsSL https://tailscale.com/install.sh | sh
```

Then connect it to your account:

```bash
sudo tailscale up
```

This prints a URL. Open it in any browser and log in with the same account from Step 1. Once you approve the device, your Pi is on your tailnet.

Verify it's connected:

```bash
tailscale status
```

You should see your Pi listed with a `100.x.x.x` IP address.

---

## Step 3: Enable HTTPS Certificates

Tailscale can issue real Let's Encrypt certificates for your devices, but this feature needs to be turned on in the admin console.

1. Go to https://login.tailscale.com/admin/dns
2. Scroll down to **HTTPS Certificates**
3. Click **Enable HTTPS**

That's it. Your devices can now request trusted certificates.

---

## Step 4: Generate Certificates for StoreCard

On your Raspberry Pi, in the StoreCard directory:

```bash
cd ~/storecard
./setup-https.sh
```

The script will:
- Detect your Pi's Tailscale hostname automatically
- Fetch a real Let's Encrypt certificate via Tailscale
- Save everything to `certs/`

If it asks for your password, that's for `sudo` — Tailscale needs root access to generate certificates.

---

## Step 5: Restart StoreCard

```bash
./storecard restart
```

You should see output like:

```
StoreCard is running at http://localhost:2222
Starting HTTPS proxy...
HTTPS available at https://raspberrypi.your-tailnet.ts.net:2223
```

---

## Step 6: Install Tailscale on Your Phone

**iPhone:**
1. Open the App Store
2. Search for "Tailscale"
3. Install it
4. Open the app and sign in with the same account from Step 1
5. Toggle the connection ON

**Android:**
1. Open the Play Store
2. Search for "Tailscale"
3. Install it
4. Open the app and sign in with the same account from Step 1
5. Toggle the connection ON

---

## Step 7: Open StoreCard on Your Phone

Open your phone's browser and go to:

```
https://raspberrypi.your-tailnet.ts.net:2223
```

Replace `raspberrypi.your-tailnet.ts.net` with whatever hostname the setup script showed you in Step 4.

You should see a green lock icon — no certificate warnings. The PWA install prompt, service workers, and camera access will all work.

**Bookmark it or add it to your home screen** — this is your StoreCard URL from now on.

---

## Renewing Certificates

Let's Encrypt certificates expire after 90 days. When they expire, just re-run:

```bash
cd ~/storecard
./setup-https.sh
./storecard restart
```

---

## Troubleshooting

### "Tailscale is not installed"
Run the install command from Step 2 again.

### "Tailscale is not connected"
```bash
sudo tailscale up
```
Then approve the device in your browser if prompted.

### "Could not determine Tailscale hostname"
Make sure Tailscale is connected (`tailscale status` should show your device). If you just installed it, wait a few seconds and try again.

### Certificate fetch fails
Make sure you enabled HTTPS certificates in the admin console (Step 3). Go to https://login.tailscale.com/admin/dns and check that HTTPS is enabled.

### Phone can't reach the Pi
- Make sure Tailscale is running on both your phone AND the Pi
- Check both devices show as "connected" in the Tailscale app
- Try pinging the Pi from your phone: open https://login.tailscale.com/admin/machines to see both devices listed

### "HTTPS proxy stopped" in status
Check the HTTPS proxy log:
```bash
cat .storecard-https.log
```
Usually this means the certificates are expired or missing. Re-run `./setup-https.sh`.
