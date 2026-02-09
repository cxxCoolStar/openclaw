/**
 * Two-Factor Authentication Manager for high-risk command verification.
 * Manages the 2FA flow: generate auth request -> wait for verification -> verify code.
 */

import crypto from "node:crypto";

export type TwoFactorRequestStatus = "pending" | "verified" | "expired" | "cancelled";

export type TwoFactorRequest = {
  id: string;
  command: string;
  verificationCode: string;
  createdAtMs: number;
  expiresAtMs: number;
  status: TwoFactorRequestStatus;
  sessionKey?: string;
  agentId?: string;
  channelId?: string;
  userId?: string;
  resolvedAtMs?: number;
};

export type TwoFactorRequestPayload = {
  command: string;
  sessionKey?: string;
  agentId?: string;
  channelId?: string;
  userId?: string;
};

export type TwoFactorConfig = {
  enabled: boolean;
  timeoutSeconds: number;
  authBaseUrl: string;
  codeLength?: number;
  mock?: {
    enabled?: boolean;
    authUrl?: string;
    code?: string;
  };
};

type PendingEntry = {
  request: TwoFactorRequest;
  resolve: (verified: boolean) => void;
  timer: ReturnType<typeof setTimeout>;
};

const DEFAULT_CODE_LENGTH = 6;
const DEFAULT_TIMEOUT_SECONDS = 300; // 5 minutes

/**
 * Generate a random alphanumeric verification code.
 */
function generateVerificationCode(length: number): string {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // Avoid confusing chars (0/O, 1/I)
  let code = "";
  const randomBytes = crypto.randomBytes(length);
  for (let i = 0; i < length; i++) {
    code += chars[randomBytes[i] % chars.length];
  }
  return code;
}

/**
 * Two-Factor Authentication Manager.
 * Handles the lifecycle of 2FA verification requests.
 */
export class TwoFactorAuthManager {
  private pending = new Map<string, PendingEntry>();
  private config: TwoFactorConfig;

  constructor(config: TwoFactorConfig) {
    this.config = config;
  }

  /**
   * Check if 2FA is enabled.
   */
  isEnabled(): boolean {
    return this.config.enabled;
  }

  /**
   * Create a new 2FA verification request.
   */
  create(payload: TwoFactorRequestPayload): TwoFactorRequest {
    const now = Date.now();
    const timeoutMs = (this.config.timeoutSeconds ?? DEFAULT_TIMEOUT_SECONDS) * 1000;
    const codeLength = this.config.codeLength ?? DEFAULT_CODE_LENGTH;
    const mockCode =
      this.config.mock?.enabled === true
        ? this.config.mock.code?.trim() || "123456"
        : null;

    const request: TwoFactorRequest = {
      id: crypto.randomUUID(),
      command: payload.command,
      verificationCode: mockCode ?? generateVerificationCode(codeLength),
      createdAtMs: now,
      expiresAtMs: now + timeoutMs,
      status: "pending",
      sessionKey: payload.sessionKey,
      agentId: payload.agentId,
      channelId: payload.channelId,
      userId: payload.userId,
    };

    return request;
  }

  /**
   * Get the authentication URL for a request.
   */
  getAuthUrl(requestId: string): string {
    const mockUrl = this.config.mock?.enabled ? this.config.mock.authUrl?.trim() : undefined;
    if (mockUrl) {
      if (mockUrl.includes("{requestId}")) {
        return mockUrl.replace("{requestId}", requestId);
      }
      const joiner = mockUrl.includes("?") ? "&" : "?";
      return `${mockUrl}${joiner}requestId=${encodeURIComponent(requestId)}`;
    }
    const baseUrl = this.config.authBaseUrl.replace(/\/$/, "");
    return `${baseUrl}/2fa/verify/${requestId}`;
  }

  /**
   * Wait for user to complete 2FA verification.
   * Returns true if verified, false if expired/cancelled.
   */
  async waitForVerification(request: TwoFactorRequest): Promise<boolean> {
    const timeoutMs = request.expiresAtMs - Date.now();
    if (timeoutMs <= 0) {
      request.status = "expired";
      return false;
    }

    return await new Promise<boolean>((resolve) => {
      const timer = setTimeout(() => {
        this.pending.delete(request.id);
        request.status = "expired";
        resolve(false);
      }, timeoutMs);

      this.pending.set(request.id, { request, resolve, timer });
    });
  }

  /**
   * Verify a code submitted by the user.
   * Returns true if the code matches and marks the request as verified.
   */
  verify(requestId: string, code: string): { success: boolean; error?: string } {
    const pending = this.pending.get(requestId);
    if (!pending) {
      return { success: false, error: "Request not found or expired" };
    }

    const { request, resolve, timer } = pending;

    // Check if expired
    if (Date.now() > request.expiresAtMs) {
      clearTimeout(timer);
      this.pending.delete(requestId);
      request.status = "expired";
      resolve(false);
      return { success: false, error: "Request expired" };
    }

    // Normalize codes for comparison (uppercase, trim)
    const normalizedInput = code.trim().toUpperCase();
    const normalizedExpected = request.verificationCode.trim().toUpperCase();

    if (normalizedInput !== normalizedExpected) {
      return { success: false, error: "Invalid verification code" };
    }

    // Mark as verified
    clearTimeout(timer);
    this.pending.delete(requestId);
    request.status = "verified";
    request.resolvedAtMs = Date.now();
    resolve(true);

    return { success: true };
  }

  /**
   * Cancel a pending verification request.
   */
  cancel(requestId: string): boolean {
    const pending = this.pending.get(requestId);
    if (!pending) {
      return false;
    }

    clearTimeout(pending.timer);
    this.pending.delete(requestId);
    pending.request.status = "cancelled";
    pending.resolve(false);
    return true;
  }

  /**
   * Get a pending request by ID.
   */
  getRequest(requestId: string): TwoFactorRequest | null {
    return this.pending.get(requestId)?.request ?? null;
  }

  /**
   * Get count of pending requests.
   */
  getPendingCount(): number {
    return this.pending.size;
  }
}

// Singleton instance (will be initialized with config)
const GLOBAL_KEY = "__OPENCLAW_2FA_MANAGER__";

export function initTwoFactorAuth(config: TwoFactorConfig): TwoFactorAuthManager {
  const manager = new TwoFactorAuthManager(config);
  (globalThis as any)[GLOBAL_KEY] = manager;
  return manager;
}

export function getTwoFactorAuthManager(): TwoFactorAuthManager | null {
  return (globalThis as any)[GLOBAL_KEY] || null;
}
