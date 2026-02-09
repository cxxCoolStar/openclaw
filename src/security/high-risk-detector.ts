/**
 * High-risk command detector for 2FA enforcement.
 * Detects potentially dangerous commands that require secondary authentication.
 */

export type HighRiskPattern = {
  id: string;
  pattern: RegExp;
  description: string;
  severity: "critical" | "high" | "medium";
};

// Default high-risk patterns
const DEFAULT_HIGH_RISK_PATTERNS: HighRiskPattern[] = [
  {
    id: "rm-recursive",
    pattern: /^rm\s+(-[a-zA-Z]*r[a-zA-Z]*|-[a-zA-Z]*f[a-zA-Z]*|--recursive|--force)\s+/i,
    description: "Recursive or forced file deletion",
    severity: "critical",
  },
  {
    id: "sudo",
    pattern: /^(sudo|doas)\s+/i,
    description: "Elevated privilege command",
    severity: "high",
  },
  {
    id: "drop-database",
    pattern: /\bdrop\s+(database|table|schema)\b/i,
    description: "Database object deletion",
    severity: "critical",
  },
  {
    id: "git-force-push",
    pattern: /^git\s+push\s+(-[a-zA-Z]*f[a-zA-Z]*|--force)/i,
    description: "Git force push",
    severity: "high",
  },
  {
    id: "kubectl-delete",
    pattern: /^kubectl\s+delete\s+/i,
    description: "Kubernetes resource deletion",
    severity: "high",
  },
  {
    id: "docker-cleanup",
    pattern: /^docker\s+(rm|rmi|system\s+prune|container\s+prune|image\s+prune)/i,
    description: "Docker resource cleanup",
    severity: "medium",
  },
  {
    id: "chmod-dangerous",
    pattern: /^chmod\s+(-[a-zA-Z]*R[a-zA-Z]*|--recursive)\s+[0-7]*[0-7][0-7][0-7]\s+\//i,
    description: "Recursive chmod on root paths",
    severity: "critical",
  },
  {
    id: "chown-dangerous",
    pattern: /^chown\s+(-[a-zA-Z]*R[a-zA-Z]*|--recursive)\s+/i,
    description: "Recursive ownership change",
    severity: "high",
  },
  {
    id: "format-disk",
    pattern: /^(mkfs|fdisk|parted|dd\s+if=)/i,
    description: "Disk formatting or low-level operations",
    severity: "critical",
  },
  {
    id: "truncate-table",
    pattern: /\btruncate\s+table\b/i,
    description: "Database table truncation",
    severity: "critical",
  },
  {
    id: "2fa-test",
    pattern: /^2fa-test$/i,
    description: "Manual 2FA test command",
    severity: "medium",
  },
];

export type HighRiskDetectionResult = {
  isHighRisk: boolean;
  matchedPattern?: HighRiskPattern;
  command: string;
};

export type HighRiskDetectorConfig = {
  enabled: boolean;
  customPatterns?: HighRiskPattern[];
  disabledPatternIds?: string[];
};

/**
 * Detects if a command is high-risk and requires 2FA.
 */
export function detectHighRiskCommand(
  command: string,
  config?: HighRiskDetectorConfig,
): HighRiskDetectionResult {
  const trimmedCommand = command.trim();

  if (!config?.enabled) {
    return { isHighRisk: false, command: trimmedCommand };
  }

  const disabledIds = new Set(config.disabledPatternIds ?? []);
  const patterns = [
    ...DEFAULT_HIGH_RISK_PATTERNS.filter((p) => !disabledIds.has(p.id)),
    ...(config.customPatterns ?? []),
  ];

  for (const pattern of patterns) {
    if (pattern.pattern.test(trimmedCommand)) {
      return {
        isHighRisk: true,
        matchedPattern: pattern,
        command: trimmedCommand,
      };
    }
  }

  return { isHighRisk: false, command: trimmedCommand };
}

/**
 * Get all available high-risk patterns (default + custom).
 */
export function getHighRiskPatterns(config?: HighRiskDetectorConfig): HighRiskPattern[] {
  const disabledIds = new Set(config?.disabledPatternIds ?? []);
  return [
    ...DEFAULT_HIGH_RISK_PATTERNS.filter((p) => !disabledIds.has(p.id)),
    ...(config?.customPatterns ?? []),
  ];
}

/**
 * Check if high-risk detection is enabled.
 */
export function isHighRiskDetectionEnabled(config?: HighRiskDetectorConfig): boolean {
  return config?.enabled ?? false;
}
