export type SecurityConfig = {
  /**
   * Two-Factor Authentication configuration.
   */
  twoFactor?: {
    /** Whether 2FA is globally enabled. Default: false. */
    enabled?: boolean;
    /** Timeout in seconds for verification requests. Default: 300. */
    timeoutSeconds?: number;
    /** Base URL for authentication. If omitted, will resolve from gateway config. */
    authBaseUrl?: string;
    /** Length of the verification code. Default: 6. */
    codeLength?: number;
    mock?: {
      enabled?: boolean;
      authUrl?: string;
      code?: string;
    };
    /**
     * High-risk command detection settings.
     */
    highRiskCommands?: {
      /** Whether to enable high-risk command detection for 2FA. Default: true (if twoFactor.enabled). */
      enabled?: boolean;
      /** IDs of default patterns to disable. */
      disabledPatternIds?: string[];
      /** Custom high-risk patterns to add. Patterns are regular expressions. */
      customPatterns?: {
        id: string;
        pattern: string;
        description: string;
        severity: "critical" | "high" | "medium";
      }[];
    };
  };
};
