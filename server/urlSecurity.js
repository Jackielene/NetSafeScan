const dns = require('dns').promises;
const { parse } = require('url');
const tldjs = require('tldjs');

// Common brand names to check for typosquatting
const COMMON_BRANDS = [
  'google', 'facebook', 'amazon', 'apple', 'microsoft', 'netflix',
  'paypal', 'twitter', 'instagram', 'linkedin', 'youtube'
];

// Common TLDs to check for lookalike domains
const COMMON_TLDS = ['.com', '.net', '.org', '.co', '.io'];

// Add whitelist for common legitimate domains
const LEGITIMATE_DOMAINS = [
  'google.com',
  'facebook.com',
  'amazon.com',
  'apple.com',
  'microsoft.com',
  'netflix.com',
  'paypal.com',
  'twitter.com',
  'instagram.com',
  'linkedin.com',
  'youtube.com',
  'github.com',
  'stackoverflow.com',
  'medium.com',
  'wikipedia.org',
  'reddit.com',
  'spotify.com',
  'dropbox.com',
  'wordpress.com',
  'cloudflare.com'
];

// Function to check if domain is whitelisted
function isWhitelistedDomain(url) {
  const domain = tldjs.getDomain(url);
  return LEGITIMATE_DOMAINS.some(legitDomain => domain === legitDomain);
}

// Function to check for typosquatting
async function checkTyposquatting(url) {
  const domain = tldjs.getDomain(url);
  const hostname = parse(url).hostname;
  
  for (const brand of COMMON_BRANDS) {
    if (domain.includes(brand)) {
      // Check for common typos
      const typos = [
        brand.replace('o', '0'),
        brand.replace('i', '1'),
        brand.replace('e', '3'),
        brand + 's',
        brand + 'shop',
        brand + 'store'
      ];
      
      for (const typo of typos) {
        if (domain.includes(typo)) {
          return {
            isTyposquatting: true,
            originalBrand: brand,
            suspiciousDomain: domain
          };
        }
      }
    }
  }
  return { isTyposquatting: false };
}

// Function to check for lookalike domains
function checkLookalikeDomain(url) {
  const domain = tldjs.getDomain(url);
  const hostname = parse(url).hostname;
  
  // Check for common lookalike characters
  const lookalikes = {
    'o': ['0', 'о', 'ο'],
    'i': ['1', 'l', '|'],
    'e': ['3', 'е'],
    'a': ['а', 'α'],
    's': ['5', 'ѕ']
  };
  
  for (const [original, similar] of Object.entries(lookalikes)) {
    for (const char of similar) {
      if (domain.includes(char)) {
        return {
          isLookalike: true,
          suspiciousChar: char,
          originalChar: original
        };
      }
    }
  }
  return { isLookalike: false };
}

// Function to check for fake subdomains
function checkFakeSubdomain(url) {
  const hostname = parse(url).hostname;
  const parts = hostname.split('.');
  
  if (parts.length > 3) {
    const suspiciousSubdomains = ['secure', 'login', 'account', 'verify', 'update'];
    const subdomain = parts[0].toLowerCase();
    
    if (suspiciousSubdomains.includes(subdomain)) {
      return {
        isFakeSubdomain: true,
        suspiciousSubdomain: subdomain
      };
    }
  }
  return { isFakeSubdomain: false };
}

// Function to check for IP address usage
function checkIPAddress(url) {
  const hostname = parse(url).hostname;
  const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
  
  if (ipPattern.test(hostname)) {
    return {
      isIPAddress: true,
      ip: hostname
    };
  }
  return { isIPAddress: false };
}

// Function to check for HTTPS
function checkHTTPS(url) {
  const protocol = parse(url).protocol;
  return {
    hasHTTPS: protocol === 'https:',
    protocol: protocol
  };
}

// Function to check for suspicious query strings
function checkQueryString(url) {
  const parsed = parse(url, true);
  const suspiciousParams = ['password', 'token', 'key', 'secret', 'auth'];
  
  if (parsed.query) {
    for (const param of suspiciousParams) {
      if (Object.keys(parsed.query).some(key => key.toLowerCase().includes(param))) {
        return {
          hasSuspiciousQuery: true,
          suspiciousParam: param
        };
      }
    }
  }
  return { hasSuspiciousQuery: false };
}

// Function to check for URL redirects
async function checkRedirects(url) {
  try {
    const response = await fetch(url, { method: 'HEAD', redirect: 'manual' });
    if (response.status >= 300 && response.status < 400) {
      return {
        hasRedirect: true,
        statusCode: response.status,
        location: response.headers.get('location')
      };
    }
  } catch (error) {
    console.error('Error checking redirects:', error);
  }
  return { hasRedirect: false };
}

// Function to check for suspicious domain patterns
function checkSuspiciousDomainPatterns(url) {
  // Skip checks for whitelisted domains
  if (isWhitelistedDomain(url)) {
    return {
      hasSuspiciousPatterns: false,
      issues: []
    };
  }

  const hostname = parse(url).hostname;
  const patterns = {
    tooManyHyphens: /-{3,}/, // Changed from 2 to 3 hyphens
    randomChars: /[a-z0-9]{15,}/i, // Increased from 10 to 15 characters
    unusualTLD: /\.(xyz|top|loan|click|work|site|online|space|website|tech|store|shop|club|info|biz|pro|app|dev|io|co|me|net|org|com)$/i,
    longUrl: /.{150,}/, // Increased from 100 to 150 characters
    suspiciousSubdomains: /(secure|login|account|verify|update|signin|signup|password|reset|confirm|validate|check|verify|update|secure|login|account|verify|update)\./i
  };

  const issues = [];
  
  if (patterns.tooManyHyphens.test(hostname)) {
    issues.push('Too many hyphens in domain');
  }
  if (patterns.randomChars.test(hostname)) {
    issues.push('Suspicious random characters in domain');
  }
  if (patterns.unusualTLD.test(hostname)) {
    issues.push('Unusual or suspicious TLD');
  }
  if (patterns.longUrl.test(url)) {
    issues.push('URL is unusually long');
  }
  if (patterns.suspiciousSubdomains.test(hostname)) {
    issues.push('Suspicious subdomain detected');
  }

  return {
    hasSuspiciousPatterns: issues.length > 0,
    issues
  };
}

// Function to check for character substitutions
function checkCharacterSubstitutions(url) {
  // Skip checks for whitelisted domains
  if (isWhitelistedDomain(url)) {
    return {
      hasSubstitutions: false,
      issues: []
    };
  }

  const hostname = parse(url).hostname;
  const substitutions = {
    'a': ['а', 'α', 'а', '@'],
    'e': ['е', 'е', '3', '€'],
    'i': ['і', 'і', '1', '!'],
    'o': ['о', 'ο', '0', 'о'],
    's': ['ѕ', 'ѕ', '5', '$'],
    't': ['т', 'т', '7', '+'],
    'l': ['l', '1', '|', 'I'],
    'g': ['ɡ', 'ɡ', '9', '&']
  };

  const issues = [];
  
  for (const [original, similar] of Object.entries(substitutions)) {
    for (const char of similar) {
      if (hostname.includes(char)) {
        issues.push(`Suspicious character substitution: ${char} for ${original}`);
      }
    }
  }

  return {
    hasSubstitutions: issues.length > 0,
    issues
  };
}

// Main function to perform all security checks
async function performSecurityChecks(url) {
  try {
    // Skip all checks for whitelisted domains
    if (isWhitelistedDomain(url)) {
      return {
        safe: true,
        threats: [],
        details: {
          isWhitelisted: true,
          domain: tldjs.getDomain(url)
        }
      };
    }

    const [
      typosquatting,
      lookalike,
      fakeSubdomain,
      ipAddress,
      https,
      queryString,
      redirects,
      suspiciousPatterns,
      characterSubstitutions
    ] = await Promise.all([
      checkTyposquatting(url),
      checkLookalikeDomain(url),
      checkFakeSubdomain(url),
      checkIPAddress(url),
      checkHTTPS(url),
      checkQueryString(url),
      checkRedirects(url),
      checkSuspiciousDomainPatterns(url),
      checkCharacterSubstitutions(url)
    ]);

    const threats = [];
    if (typosquatting.isTyposquatting) threats.push('Typosquatting');
    if (lookalike.isLookalike) threats.push('Lookalike Domain');
    if (fakeSubdomain.isFakeSubdomain) threats.push('Fake Subdomain');
    if (ipAddress.isIPAddress) threats.push('Direct IP Address');
    if (!https.hasHTTPS) threats.push('No HTTPS');
    if (queryString.hasSuspiciousQuery) threats.push('Suspicious Query String');
    if (redirects.hasRedirect) threats.push('Suspicious Redirect');
    if (suspiciousPatterns.hasSuspiciousPatterns) threats.push(...suspiciousPatterns.issues);
    if (characterSubstitutions.hasSubstitutions) threats.push(...characterSubstitutions.issues);

    return {
      safe: threats.length === 0,
      threats,
      details: {
        typosquatting,
        lookalike,
        fakeSubdomain,
        ipAddress,
        https,
        queryString,
        redirects,
        suspiciousPatterns,
        characterSubstitutions
      }
    };
  } catch (error) {
    console.error('Error performing security checks:', error);
    throw error;
  }
}

module.exports = {
  performSecurityChecks,
  LEGITIMATE_DOMAINS
}; 