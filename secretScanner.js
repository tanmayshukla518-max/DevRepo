/**
 * secretScanner.js
 * 
 * Scans files and strings for sensitive credentials.
 */

const SECRET_PATTERNS = [
  {
    name: "AWS Access Key",
    pattern: /AKIA[0-9A-Z]{16}/i,
    severity: "critical",
    recommendation: "Rotate AWS access key immediately via IAM console."
  },
  {
    name: "AWS Secret Key",
    pattern: /aws[_\-]?secret[_\-]?key/i,
    severity: "critical",
    recommendation: "Remove secret from codebase and rotate credentials."
  },
  {
    name: "Generic API Key",
    pattern: /api[_\-]?key\s*[:=]\s*['"][^'"]{8,}/i,
    severity: "high",
    recommendation: "Move API key to environment variables or secrets manager."
  },
  {
    name: "Generic Password",
    pattern: /password\s*[:=]\s*['"][^'"]{4,}/i,
    severity: "critical",
    recommendation: "Never commit passwords. Use env vars or vault."
  },
  {
    name: "Private Key Block",
    pattern: /-----BEGIN\s+(?:RSA\s+)?PRIVATE KEY-----/,
    severity: "critical",
    recommendation: "Revoke and regenerate the private key immediately."
  },
  {
    name: "GitHub Token",
    pattern: /gh[ps]_[A-Za-z0-9]{36}/,
    severity: "critical",
    recommendation: "Revoke token on GitHub and generate a new one."
  },
  {
    name: "Slack Token",
    pattern: /xox[bapr]-[0-9a-zA-Z]{10,48}/,
    severity: "critical",
    recommendation: "Revoke Slack token in your Slack App console."
  }
];

function scanForSecrets(title = "", message = "") {
  const haystack = `${title} ${message}`.trim();
  const findings = [];

  for (const pattern of SECRET_PATTERNS) {
    if (pattern.pattern.test(haystack)) {
      findings.push({
        name: pattern.name,
        severity: pattern.severity,
        recommendation: pattern.recommendation,
        matched: true
      });
    }
  }

  const unique = {};
  for (const f of findings) {
    if (!unique[f.name] || severityRank(f.severity) < severityRank(unique[f.name].severity)) {
      unique[f.name] = f;
    }
  }

  return Object.values(unique);
}

function severityRank(s) {
  return { critical: 0, high: 1, medium: 2, low: 3 }[s] ?? 4;
}

function hasSecretLeak(title, message) {
  return scanForSecrets(title, message).some(
    (f) => f.severity === "critical" || f.severity === "high"
  );
}

module.exports = { scanForSecrets, hasSecretLeak };
