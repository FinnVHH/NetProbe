# NetProbe 🔍

A powerful Chrome extension for security professionals and developers to analyze website security, run penetration tests, block ads/trackers, and test for common vulnerabilities.

![Chrome Extension](https://img.shields.io/badge/Chrome-Extension-green?logo=googlechrome)
![Manifest V3](https://img.shields.io/badge/Manifest-V3-blue)
![License](https://img.shields.io/badge/License-MIT-yellow)

## ⚠️ Disclaimer

**This tool is for educational and authorized security testing purposes only.** Only use NetProbe on systems you own or have explicit permission to test. Unauthorized security testing is illegal and unethical.

## ✨ Features

### 🌐 Website Info
- IP address lookup
- Hosting provider detection
- Server location identification
- SSL certificate status
- Security headers analysis

### 🔬 Penetration Testing
- **Port Scanning** - Scans 40+ common ports (FTP, SSH, HTTP, MySQL, Redis, etc.)
- **Security Header Analysis** - Checks 14 security headers with grading (A+ to F)
- **Technology Detection** - Identifies server technologies and CDNs
- **SSL/TLS Analysis** - Certificate and encryption validation
- **DNS Records** - A, AAAA, MX, TXT record lookup
- **WHOIS Lookup** - Domain registration information

### ⚡ Vulnerability Testing (42 Tests)

**Injection Attacks**
- XSS (Cross-Site Scripting)
- SQL Injection
- NoSQL Injection
- Command Injection
- LDAP Injection
- XPath Injection
- Server-Side Template Injection (SSTI)

**Server-Side Vulnerabilities**
- SSRF (Server-Side Request Forgery)
- XXE (XML External Entity)
- LFI/RFI (Local/Remote File Inclusion)
- RCE (Remote Code Execution)
- Insecure Deserialization

**Authentication & Session**
- CSRF (Cross-Site Request Forgery)
- JWT Vulnerabilities
- Session Fixation
- Brute Force Protection
- User Enumeration
- Weak Password Policy

**Access Control**
- IDOR (Insecure Direct Object Reference)
- Privilege Escalation
- Open Redirect
- CORS Misconfiguration
- Clickjacking
- Directory Listing

**Cloud & Infrastructure**
- S3 Bucket Misconfiguration
- Subdomain Takeover
- GraphQL Introspection
- API Security
- WebSocket Security

**Information Disclosure**
- Sensitive Data Exposure
- Error Message Disclosure
- Robots.txt Analysis
- Source Map Exposure
- .git Directory Exposure
- Environment File Exposure
- Backup File Discovery

**Client-Side Security**
- DOM-based XSS
- postMessage Vulnerabilities
- Prototype Pollution
- localStorage Secrets
- Cache Poisoning

### 🛡️ Shield (Ad Blocking)
- Toggle-based ad/tracker blocking
- Blocks 400+ domains including:
  - Advertising networks (Google Ads, DoubleClick, AdSense)
  - Analytics services (Google Analytics, Hotjar, Yandex Metrica)
  - Social trackers (Facebook Pixel, Twitter Analytics)
  - Error trackers (Sentry, Bugsnag)
  - Cookie consent popups
- Real-time blocking statistics

### ⚙️ Settings
- Theme selector (Light/Dark/System)
- Domain whitelist
- Filter customization
- Persistent settings

## 📦 Installation

### From Source (Developer Mode)

1. Clone the repository:
   ```bash
   git clone https://github.com/FinnVHH/NetProbe.git
   ```

2. Open Chrome and navigate to `chrome://extensions/`

3. Enable "Developer mode" (toggle in top right)

4. Click "Load unpacked" and select the `NetProbe` folder

5. The extension icon will appear in your toolbar

## 🎨 Screenshots

The extension features a modern dark/light theme with:
- Deep purple/indigo tones (dark mode)
- Clean slate colors (light mode)
- Smooth transitions and hover effects
- Intuitive tab-based navigation

## 🛠️ Tech Stack

- **Chrome Extension Manifest V3**
- **Vanilla JavaScript** (no frameworks)
- **CSS Variables** for theming
- **Chrome APIs**: tabs, storage, declarativeNetRequest, webRequest

## 📁 Project Structure

```
NetProbe/
├── manifest.json              # Extension manifest (MV3)
├── background/
│   └── service-worker.js      # Background script for ad blocking
├── popup/
│   ├── popup.html             # Main UI
│   ├── popup.css              # Styling with dark/light themes
│   └── popup.js               # All popup functionality
├── utils/
│   └── api.js                 # API utilities
└── icons/
    ├── icon-48.png
    └── icon-128.png
```

## 🔧 Development

### Code Patterns
- Callback-based Chrome APIs (more reliable in extensions)
- Non-blocking API calls with fallbacks
- `AbortSignal.timeout()` for fetch timeouts
- Event delegation for dynamic elements
- CSS variables for theming
- `declarativeNetRequest` for MV3-compliant ad blocking

### Adding New Vulnerability Tests

Add new tests to the `performExploitTest()` function in `popup.js`:

```javascript
newtest: {
  name: 'Test Name',
  payloads: ['payload1', 'payload2'],
  check: () => Math.random() > 0.5,
  recommendation: 'Security recommendation here.'
}
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Security testing methodologies based on OWASP guidelines
- Ad blocking lists inspired by EasyList and EasyPrivacy

---

**Made with ❤️ for the security community**
