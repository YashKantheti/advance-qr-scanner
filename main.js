// main.js - Electron main process
const { app, BrowserWindow, ipcMain, shell } = require('electron');
const path = require('path');
const url = require('url');
const axios = require('axios');
const crypto = require('crypto');
const fs = require('fs');
const isDev = process.env.NODE_ENV === 'development';

// Database to store scan history and known malicious content
let scanHistoryDB = [];
let knownThreatsDB = [];

// Load databases from local storage
try {
  if (fs.existsSync(path.join(app.getPath('userData'), 'scanHistory.json'))) {
    scanHistoryDB = JSON.parse(fs.readFileSync(path.join(app.getPath('userData'), 'scanHistory.json')));
  }
  
  if (fs.existsSync(path.join(app.getPath('userData'), 'knownThreats.json'))) {
    knownThreatsDB = JSON.parse(fs.readFileSync(path.join(app.getPath('userData'), 'knownThreats.json')));
  }
} catch (error) {
  console.error('Error loading databases:', error);
}

let mainWindow;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 900,
    height: 700,
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false,
      enableRemoteModule: true
    }
  });

  mainWindow.loadURL(
    url.format({
      pathname: path.join(__dirname, 'index.html'),
      protocol: 'file:',
      slashes: true
    })
  );

  if (isDev) {
    mainWindow.webContents.openDevTools();
  }

  mainWindow.on('closed', function () {
    mainWindow = null;
  });
}

// Additional IPC handlers
ipcMain.handle('save-threat', async (event, threat) => {
  // Add to known threats database
  const contentHash = crypto.createHash('sha256').update(threat.content).digest('hex');
  
  knownThreatsDB.push({
    contentHash,
    content: threat.content,
    type: threat.type,
    reason: threat.reason,
    dateAdded: new Date().toISOString()
  });
  
  // Save to file
  try {
    fs.writeFileSync(
      path.join(app.getPath('userData'), 'knownThreats.json'),
      JSON.stringify(knownThreatsDB)
    );
    return { success: true };
  } catch (error) {
    console.error('Error saving threat:', error);
    return { success: false, error: error.message };
  }
});

ipcMain.handle('save-scan', async (event, scan) => {
  // Add to scan history
  scanHistoryDB.push({
    content: scan.content,
    riskLevel: scan.riskLevel,
    type: scan.type,
    timestamp: new Date().toISOString()
  });
  
  // Keep only last 100 scans
  if (scanHistoryDB.length > 100) {
    scanHistoryDB = scanHistoryDB.slice(-100);
  }
  
  // Save to file
  try {
    fs.writeFileSync(
      path.join(app.getPath('userData'), 'scanHistory.json'),
      JSON.stringify(scanHistoryDB)
    );
    return { success: true };
  } catch (error) {
    console.error('Error saving scan:', error);
    return { success: false, error: error.message };
  }
});

ipcMain.handle('get-scan-history', async () => {
  return scanHistoryDB;
});

// Safe URL handling
ipcMain.handle('open-url-safely', async (event, urlToOpen) => {
  try {
    // Perform additional safety checks before opening
    const url = new URL(urlToOpen);
    
    // Check if the domain is in a known safe list (example)
    const safeDomains = ['google.com', 'github.com', 'microsoft.com', 'apple.com'];
    const domainIsSafe = safeDomains.some(domain => url.hostname === domain || url.hostname.endsWith('.' + domain));
    
    if (domainIsSafe) {
      // Open directly if domain is known safe
      shell.openExternal(urlToOpen);
      return { success: true, message: 'URL opened successfully' };
    } else {
      // For other domains, warn the user
      const { response } = await dialog.showMessageBox({
        type: 'warning',
        buttons: ['Cancel', 'Open Anyway'],
        defaultId: 0,
        title: 'Potentially Unsafe URL',
        message: 'This URL may be unsafe:',
        detail: `${urlToOpen}\n\nWould you like to proceed anyway?`,
        checkboxLabel: 'Don\'t warn me again for this domain',
        checkboxChecked: false
      });
      
      if (response === 1) { // User clicked "Open Anyway"
        shell.openExternal(urlToOpen);
        return { success: true, message: 'URL opened by user confirmation' };
      } else {
        return { success: false, message: 'User cancelled opening URL' };
      }
    }
  } catch (error) {
    console.error('Error opening URL:', error);
    return { success: false, error: error.message };
  }
});

ipcMain.handle('check-url-reputation', async (event, urlToCheck) => {
  // In a production app, we would call a real API like VirusTotal, Google Safe Browsing, etc.
  // For this example, we'll simulate the API call with a delay
  await new Promise(resolve => setTimeout(resolve, 1000));
  
  try {
    const url = new URL(urlToCheck);
    const domain = url.hostname;
    
    // Simulate reputation check result
    const reputationScore = Math.random();
    let reputation;
    
    if (reputationScore > 0.95) {
      reputation = "malicious";
    } else if (reputationScore > 0.85) {
      reputation = "suspicious";
    } else if (reputationScore > 0.7) {
      reputation = "neutral";
    } else {
      reputation = "safe";
    }
    
    return {
      domain,
      reputation,
      score: reputationScore.toFixed(2),
      categories: reputation === "safe" ? ["trustworthy"] : 
                 reputation === "malicious" ? ["malware", "phishing"] : 
                 ["unverified"]
    };
  } catch (error) {
    console.error('Error checking URL reputation:', error);
    return {
      error: 'Invalid URL or service unavailable',
      reputation: "unknown"
    };
  }
});

app.on('ready', createWindow);

app.on('window-all-closed', function () {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('activate', function () {
  if (mainWindow === null) {
    createWindow();
  }
});

// Handle QR code risk analysis
ipcMain.handle('analyze-qr-content', async (event, qrContent) => {
  try {
    // Check if QR code contains a URL
    let url = null;
    
    // Enhanced URL detection - handle more formats and patterns
    const urlRegex = /((?:https?|ftp):\/\/)?([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(\/[^\s]*)?/i;
    const urlMatch = qrContent.match(urlRegex);
    
    if (urlMatch) {
      url = urlMatch[0];
      // Ensure URL has protocol
      if (!url.startsWith('http://') && !url.startsWith('https://')) {
        url = 'https://' + url;
      }
    }
    
    // Check if this content has been previously identified as malicious
    const contentHash = crypto.createHash('sha256').update(qrContent).digest('hex');
    const knownThreat = knownThreatsDB.find(threat => threat.contentHash === contentHash);
    
    if (knownThreat) {
      return {
        riskLevel: 'high',
        details: {
          type: 'known_threat',
          content: qrContent,
          analysis: 'This QR code has been previously identified as malicious',
          reasons: [knownThreat.reason || 'Matched against database of known threats']
        }
      };
    }
    
    // If it's a URL, perform advanced checks
    if (url) {
      try {
        // Create a URL object for analysis
        const urlObj = new URL(url);
        const domain = urlObj.hostname;
        
        // 1. Check domain age and registration info
        // This would normally use a WHOIS API
        const domainRiskFactors = [];
        
        // 2. Check against Google Safe Browsing API
        // In production, implement actual API call
        // const safeBrowsingEndpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${API_KEY}`;
        // const safeBrowsingResponse = await axios.post(safeBrowsingEndpoint, {
        //   client: { clientId: "yourCompany", clientVersion: "1.0" },
        //   threatInfo: {
        //     threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
        //     platformTypes: ["ANY_PLATFORM"],
        //     threatEntryTypes: ["URL"],
        //     threatEntries: [{ url: url }]
        //   }
        // });
        
        // 3. URL structure analysis
        // Check for suspicious patterns
        const suspiciousPatterns = [
          { pattern: /phish|malware|suspicious|scam|hack/, score: 0.8 },
          { pattern: /@/, score: 0.6 }, // URLs with @ symbols can be deceptive
          { pattern: /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/, score: 0.5 }, // IP addresses instead of domains
          { pattern: /bit\.ly|tinyurl|goo\.gl|t\.co|is\.gd|buff\.ly|ow\.ly|tr\.im/, score: 0.4 }, // URL shorteners
          { pattern: /login|signin|account|password|credential|verify|secure|update/, score: 0.3 }, // Words common in phishing
          { pattern: /\.(xyz|tk|ml|ga|cf|gq|top)$/, score: 0.3 } // TLDs often abused
        ];
        
        let riskScore = 0;
        const reasons = [];
        
        suspiciousPatterns.forEach(({ pattern, score }) => {
          if (pattern.test(url)) {
            riskScore += score;
            reasons.push(`URL contains suspicious pattern: ${pattern.toString().slice(1, -1)}`);
          }
        });
        
        // 4. Domain reputation check (simulated)
        // In production, integrate with a domain reputation API
        const maliciousDomains = ['evil.com', 'malware.com', 'phishing.com', 'scam.site'];
        if (maliciousDomains.some(d => domain.includes(d))) {
          riskScore += 1.0;
          reasons.push('Domain has known bad reputation');
        }
        
        // 5. Analyze URL parameter complexity
        if (urlObj.search && urlObj.search.length > 50) {
          riskScore += 0.2;
          reasons.push('URL contains unusually complex parameters');
        }
        
        // 6. Determine risk level based on score
        let riskLevel = 'low';
        if (riskScore >= 0.8) {
          riskLevel = 'high';
        } else if (riskScore >= 0.3) {
          riskLevel = 'medium';
        }
        
        return {
          riskLevel: riskLevel,
          details: {
            type: riskLevel === 'high' ? 'suspicious_url' : 'url',
            url: url,
            domain: domain,
            riskScore: riskScore.toFixed(2),
            reasons: reasons.length > 0 ? reasons : ['No specific threats detected']
          }
        };
      } catch (error) {
        console.error('Error checking URL safety:', error);
        return {
          riskLevel: 'medium',
          details: {
            type: 'malformed_url',
            url: url,
            reasons: ['URL structure is invalid or unusual']
          }
        };
      }
    }
    
    // Check if it's a contact (vCard)
    if (qrContent.startsWith('BEGIN:VCARD') && qrContent.includes('END:VCARD')) {
      // Parse vCard for potential risks
      const vCardRisks = [];
      
      // Look for unusual fields or potentially dangerous content
      if (qrContent.includes('URL:')) {
        const urlMatch = qrContent.match(/URL:(https?:\/\/[^\r\n]+)/i);
        if (urlMatch && urlMatch[1]) {
          // Recursively check the embedded URL
          const urlAnalysis = await this.analyzeQrContent(urlMatch[1]);
          if (urlAnalysis.riskLevel !== 'low') {
            vCardRisks.push('Contact card contains potentially suspicious URL');
          }
        }
      }
      
      // Check for scripts or HTML that could be malicious
      if (/<script|<iframe|javascript:/i.test(qrContent)) {
        vCardRisks.push('Contact card contains potentially executable code');
        return {
          riskLevel: 'high',
          details: {
            type: 'malicious_contact_card',
            content: qrContent,
            reasons: vCardRisks
          }
        };
      }
      
      return {
        riskLevel: vCardRisks.length > 0 ? 'medium' : 'low',
        details: {
          type: 'contact_info',
          content: qrContent,
          analysis: vCardRisks.length > 0 
            ? 'QR code contains contact information with potential risks' 
            : 'QR code contains standard contact information',
          reasons: vCardRisks.length > 0 ? vCardRisks : undefined
        }
      };
    }
    
    // Check if it's WiFi credentials
    if (qrContent.startsWith('WIFI:')) {
      // Parse WiFi QR code
      const ssidMatch = qrContent.match(/S:([^;]+)/);
      const securityMatch = qrContent.match(/T:([^;]+)/);
      
      const ssid = ssidMatch ? ssidMatch[1] : 'Unknown';
      const security = securityMatch ? securityMatch[1].toUpperCase() : 'Unknown';
      
      const wifiRisks = [];
      
      // Check encryption type
      if (security === 'NONE' || security === 'WEP') {
        wifiRisks.push(`Network uses insecure encryption (${security})`);
      }
      
      // Check for potentially malicious SSIDs
      const suspiciousSSIDPatterns = [
        /free\s*wifi/i,
        /public\s*wifi/i,
        /airport|hotel|cafe/i,
        /[0-9a-f]{12}/i // MAC address format, often used in spoofing
      ];
      
      for (const pattern of suspiciousSSIDPatterns) {
        if (pattern.test(ssid)) {
          wifiRisks.push('Network name matches patterns often used in rogue access points');
          break;
        }
      }
      
      return {
        riskLevel: wifiRisks.length > 0 ? 'high' : 'medium',
        details: {
          type: 'wifi_credentials',
          network: ssid,
          security: security,
          content: qrContent,
          analysis: 'QR code contains WiFi network credentials. Only connect to trusted networks.',
          reasons: wifiRisks.length > 0 ? wifiRisks : ['No specific security issues detected, but always verify WiFi networks before connecting']
        }
      };
    }
    
    // Check if it's a cryptocurrency payment request
    if (qrContent.match(/^(bitcoin|ethereum|litecoin):/i)) {
      return {
        riskLevel: 'high',
        details: {
          type: 'cryptocurrency_payment',
          content: qrContent,
          analysis: 'QR code contains cryptocurrency payment information. Verify recipient carefully before sending funds.',
          reasons: ['Cryptocurrency transactions are irreversible if sent to wrong address']
        }
      };
    }
    
    // Check if it's a calendar event
    if (qrContent.startsWith('BEGIN:VCALENDAR') && qrContent.includes('END:VCALENDAR')) {
      // Parse for URLs or suspicious content
      const calendarRisks = [];
      if (/<script|<iframe|javascript:/i.test(qrContent)) {
        calendarRisks.push('Calendar event contains potentially executable code');
      }
      
      if (/https?:\/\//i.test(qrContent)) {
        calendarRisks.push('Calendar event contains web links - verify before opening');
      }
      
      return {
        riskLevel: calendarRisks.length > 0 ? 'medium' : 'low',
        details: {
          type: 'calendar_event',
          content: qrContent,
          analysis: 'QR code contains calendar event information',
          reasons: calendarRisks.length > 0 ? calendarRisks : undefined
        }
      };
    }
    
    // Check for potentially executable content
    if (/<script|<iframe|javascript:|data:text\/html|data:application\/|ssh:|ftp:/i.test(qrContent)) {
      return {
        riskLevel: 'high',
        details: {
          type: 'potentially_executable',
          content: qrContent,
          analysis: 'QR code contains content that could execute code or access restricted resources',
          reasons: ['Contains patterns associated with executable code or protocols']
        }
      };
    }
    
    // Default response for other types of content
    return {
      riskLevel: 'unknown',
      details: {
        type: 'other',
        content: qrContent,
        analysis: 'Unknown QR code content type - inspect carefully before proceeding'
      }
    };
  } catch (error) {
    console.error('Error analyzing QR code:', error);
    return {
      riskLevel: 'error',
      details: {
        error: error.message
      }
    };
  }
});
