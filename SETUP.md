# ⚡ Zappo — Setup Guide

## What this is
A real messaging app. When you send a message to your mum,
it arrives on her phone/laptop/browser instantly — no two-tab nonsense.

Uses: Node.js + Socket.io + SQLite (no external DB needed)

---

## STEP 1 — Install Node.js (if you don't have it)
Download from https://nodejs.org → install the LTS version.
Check it works: open Terminal / Command Prompt and type:
  node --version

---

## STEP 2 — Run the server locally

  cd zappo-full
  npm install
  npm start

You'll see:
  ⚡ Zappo running → http://localhost:3000

Open http://localhost:3000 in your browser — Zappo loads.

---

## STEP 3 — Let your mum message you (same WiFi)

Find your local IP address:
  Windows:  ipconfig          → look for IPv4 Address
  Mac/Linux: ifconfig | grep inet

Tell your mum to open:  http://YOUR_IP:3000
(e.g. http://192.168.1.5:3000)

She creates an account. You create an account.
You type her username → Start Chat → messages go to her LIVE.

---

## STEP 4 — Deploy so ANYONE can message you from anywhere

### Option A — Railway (easiest, free tier)
1. Go to https://railway.app → sign up with GitHub
2. New Project → Deploy from GitHub repo
   (upload this folder to GitHub first, or use Railway CLI)
3. Railway auto-detects Node.js and runs npm start
4. Add environment variables in Railway dashboard:
     JWT_SECRET   = (generate a random string)
     GIPHY_KEY    = (optional, get free at developers.giphy.com)
5. Railway gives you a URL like: https://zappo-production.up.railway.app
6. Share that URL with anyone — they sign up and you can message each other!

### Option B — Render (also free)
1. https://render.com → New Web Service
2. Connect your GitHub repo
3. Build command:  npm install
   Start command:  npm start
4. Add env vars: JWT_SECRET, GIPHY_KEY
5. Get your public URL

### Option C — Run on your own VPS (DigitalOcean, etc.)
  git clone your-repo
  cd zappo-full && npm install
  # Install pm2 to keep it running
  npm install -g pm2
  pm2 start src/server.js --name zappo
  pm2 save

---

## STEP 5 — Get GIFs working (optional, free)

1. Go to https://developers.giphy.com/dashboard/
2. Sign up → Create App → SDK → get your API key
3. Add it to .env:  GIPHY_KEY=your_key_here
4. Restart server

---

## Features
✅ Real sign-up / sign-in (password hashed with bcrypt)
✅ Messages delivered cross-device, cross-browser, cross-network
✅ Live typing indicators
✅ Online / offline presence
✅ Emoji picker
✅ Sticker packs (Twemoji)
✅ GIF search via Giphy
✅ Unread message counts
✅ Message history (stored in SQLite)
✅ Works on mobile browsers
✅ No disposable email accounts allowed

---

## Usernames
- Only lowercase letters, numbers, underscore
- e.g.: rahul, mum_123, brother_ravi
- Share your username so others can find you
