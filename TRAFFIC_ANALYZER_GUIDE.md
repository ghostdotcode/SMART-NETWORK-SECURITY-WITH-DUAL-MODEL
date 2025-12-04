# AI Traffic Analyzer - Installation & Usage Guide

## 🎯 What This Does

This tool captures **YOUR REAL browsing traffic** and shows you:
- ✅ Every website you visit
- ✅ AI model's threat prediction for each request
- ✅ Confidence percentages for SAFE/SUSPICIOUS/MALICIOUS
- ✅ All 35+ features extracted from traffic
- ✅ Beautiful colored terminal output
- **✅ ZERO BLOCKING - Pure analysis mode**

---

## 📦 Installation

### Step 1: Install colorama (for colored output)
```bash
pip install colorama
```

---

## 🚀 How to Use

### Step 1: Start ML Model API
```bash
# Terminal 1
python app.py
```

### Step 2: Start Traffic Analyzer
```bash
# Terminal 2
python traffic_analyzer.py
```

### Step 3: Configure Your Browser Proxy

**Windows Settings:**
1. Settings → Network & Internet → Proxy
2. Toggle "Use a proxy server" to ON
3. Address: `127.0.0.1`
4. Port: `8080`
5. Save

### Step 4: Browse Normally! 🌐

Visit any website:
- `https://www.google.com` ← Will show as SAFE ✅
- `http://httpbin.org/.env` ← Will show as MALICIOUS ✗
- `http://example.com/admin` ← Will show as MALICIOUS ✗

---

## 📺 Example Output

When you visit a website, you'll see:

```
───────────────────────────────────────────────────────────────────────────

📊 Request #0001 • 17:35:42
✅ THREAT LEVEL: SAFE (Confidence: 92.3%)

🌐 Request Details:
   Method:      GET
   URL:         http://www.google.com/
   Source IP:   127.0.0.1
   Country:     LOCAL
   User-Agent:  Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0

🤖 AI Model Prediction:
   Action:      MANAGED_CHALLENGE
   Code:        0

📈 Confidence Distribution:
   ✅ MANAGED_CHALLENGE     92.3%  ██████████████████
   ⚠️  CHALLENGE             5.2%  █
   ✗  BLOCK                  2.1%  
   ✗  JSCHALLENGE           0.4%  

⚖️  Decision:
   [SAFE] Traffic ALLOWED - No threat detected

🔍 Features Analyzed:
   ✓ IP characteristics (IPv6, length, private range)
   ✓ Endpoint analysis (length, depth, query params, extensions)
   ✓ User-Agent fingerprinting (browser, OS, automation)
   ✓ Geographic risk scoring
   ✓ Temporal patterns (hour, day, weekend)
   ✓ Behavioral analysis (35+ features total)
───────────────────────────────────────────────────────────────────────────
```

For a malicious pattern like `/.env`:

```
───────────────────────────────────────────────────────────────────────────

📊 Request #0002 • 17:36:15
✗ THREAT LEVEL: MALICIOUS (Confidence: 87.5%)

🌐 Request Details:
   Method:      GET
   URL:         http://example.com/.env
   Source IP:   127.0.0.1
   Country:     LOCAL
   User-Agent:  curl/7.68.0

🤖 AI Model Prediction:
   Action:      BLOCK
   Code:        2

📈 Confidence Distribution:
   ✅ MANAGED_CHALLENGE      5.3%  █
   ⚠️  CHALLENGE             7.2%  █
   ✗  BLOCK                 87.5%  █████████████████
   ✗  JSCHALLENGE           0.0%  

⚖️  Decision:
   [MALICIOUS] Would be BLOCKED in active mode (403 Forbidden)

🔍 Features Analyzed:
   ✓ IP characteristics (IPv6, length, private range)
   ✓ Endpoint analysis (length, depth, query params, extensions)
   ✓ User-Agent fingerprinting (browser, OS, automation)
   ✓ Geographic risk scoring
   ✓ Temporal patterns (hour, day, weekend)
   ✓ Behavioral analysis (35+ features total)
───────────────────────────────────────────────────────────────────────────
```

---

## 📊 Statistics Display

Every 10 requests, you'll see:

```
───────────────────────────────────────────────────────────────────────────
📊 SESSION STATISTICS
───────────────────────────────────────────────────────────────────────────
   Total Scanned:    50
   ✅ Safe:          42 (84.0%)
   ⚠️  Suspicious:    5 (10.0%)
   ✗  Malicious:     3 (6.0%)
   Session Uptime:   0:15:32
───────────────────────────────────────────────────────────────────────────
```

---

## 🎨 Color Legend

- **Green ✅** = SAFE (MANAGED_CHALLENGE) - Traffic allowed
- **Yellow ⚠️** = SUSPICIOUS (CHALLENGE) - Would show verification
- **Red ✗** = MALICIOUS (BLOCK/JSCHALLENGE) - Would be blocked

---

## ✅ What Gets Analyzed

For **EVERY** request, the analyzer shows:

### Request Info:
- HTTP Method (GET, POST, etc.)
- Full URL/endpoint
- Your IP address
- Country (detected via GeoIP)
- User-Agent string

### AI Prediction:
- Predicted action (MANAGED_CHALLENGE, CHALLENGE, BLOCK, JSCHALLENGE)
- Numeric code (0, 1, 2, 3)
- Confidence percentages for ALL 4 categories
- Visual bar charts showing distribution

### Features Extracted:
All 35+ features your model uses:
- `Country`, `hour`, `day_of_week`, `is_weekend`
- `is_ipv6`, `ip_length`, `is_private_range`
- `endpoint_length`, `endpoint_depth`, `has_query_params`
- `suspicious_keywords`, `has_path`, `path_length`
- `ua_length`, `is_chrome`, `is_firefox`, `is_safari`
- `is_automated`, `is_bot`, `country_risk_score`
- And many more!

---

## 🎯 Testing Ideas

### Test 1: Safe Traffic
```
Visit: https://www.google.com
Visit: https://www.youtube.com
Visit: https://github.com
```
Expected: All show ✅ SAFE

### Test 2: Malicious Patterns
```
Visit: http://httpbin.org/.env
Visit: http://httpbin.org/admin
Visit: http://httpbin.org/wp-login.php
```
Expected: All show ✗ MALICIOUS

### Test 3: Your Own Website
Browse your own site and see what the AI thinks!

---

## 🔧 Customization

### Change Colors
Edit the `Fore.GREEN`, `Fore.RED`, `Fore.YELLOW` in the code

### Adjust Display
Modify `print_request_analysis()` function to show more/less info

### Export to File
Add logging to save all predictions to a file

---

## 🆘 Troubleshooting

**"Cannot reach ML Model API"**
- Make sure `python app.py` is running in another terminal

**"Port 8080 already in use"**
- Stop `ai_firewall_proxy.py` if it's running
- Or change `PROXY_PORT = 9090` in the code

**No traffic showing up**
- Make sure browser proxy is configured (127.0.0.1:8080)
- Try visiting http://httpbin.org/get to test

**Colors not showing (Windows)**
- Run: `pip install colorama`
- The script auto-initializes colorama

---

## 💡 Pro Tips

1. **Clear Terminal** - The output is cleaner with a large terminal window
2. **Browse Normally** - Just use your browser as usual, watch the magic!
3. **Take Screenshots** - The colored output looks great for presentations
4. **Compare Sites** - See how different websites score
5. **Watch Patterns** - Notice when your own IP behavior changes

---

## 🎓 What You're Learning

By watching the output, you'll understand:
- How HTTP requests work
- What headers browsers send
- How ML models analyze traffic patterns
- Why certain URLs are flagged as malicious
- How features like User-Agent, endpoint patterns matter

---

## 🚀 Next Steps

Once you've analyzed traffic:
1. You can switch back to `ai_firewall_proxy.py` for actual blocking
2. Or keep analyzing to fine-tune your model
3. Use the insights to add custom whitelist/blacklist rules

---

**Enjoy watching your AI model analyze traffic in real-time!** 🎉
