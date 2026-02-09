/**
 * Two-Factor Authentication Gateway API handlers.
 * Provides HTTP endpoints for 2FA verification flow.
 */

import type { GatewayRequestHandlers } from "./types.js";
import {
  getTwoFactorAuthManager,
  type TwoFactorRequest,
} from "../../security/two-factor-auth.js";
import { ErrorCodes, errorShape } from "../protocol/index.js";

/**
 * Create 2FA-related Gateway request handlers.
 */
export function createTwoFactorAuthHandlers(): GatewayRequestHandlers {
  return {
    /**
     * Verify a 2FA code submitted by the user.
     * Called when user enters the verification code in the chat.
     */
    "2fa.verify": async ({ params, respond }) => {
      const manager = getTwoFactorAuthManager();
      if (!manager) {
        respond(
          false,
          undefined,
          errorShape(ErrorCodes.UNAVAILABLE, "2FA not initialized"),
        );
        return;
      }

      const p = params as { requestId?: string; code?: string };
      
      if (!p.requestId || typeof p.requestId !== "string") {
        respond(
          false,
          undefined,
          errorShape(ErrorCodes.INVALID_REQUEST, "requestId is required"),
        );
        return;
      }

      if (!p.code || typeof p.code !== "string") {
        respond(
          false,
          undefined,
          errorShape(ErrorCodes.INVALID_REQUEST, "code is required"),
        );
        return;
      }

      const result = manager.verify(p.requestId, p.code);
      
      if (!result.success) {
        respond(
          false,
          undefined,
          errorShape(ErrorCodes.INVALID_REQUEST, result.error ?? "Verification failed"),
        );
        return;
      }

      respond(true, { verified: true, requestId: p.requestId }, undefined);
    },

    /**
     * Get status of a 2FA request.
     */
    "2fa.status": async ({ params, respond }) => {
      const manager = getTwoFactorAuthManager();
      if (!manager) {
        respond(
          false,
          undefined,
          errorShape(ErrorCodes.UNAVAILABLE, "2FA not initialized"),
        );
        return;
      }

      const p = params as { requestId?: string };
      
      if (!p.requestId || typeof p.requestId !== "string") {
        respond(
          false,
          undefined,
          errorShape(ErrorCodes.INVALID_REQUEST, "requestId is required"),
        );
        return;
      }

      const request = manager.getRequest(p.requestId);
      
      if (!request) {
        respond(
          false,
          undefined,
          errorShape(ErrorCodes.INVALID_REQUEST, "Request not found or expired"),
        );
        return;
      }

      respond(
        true,
        {
          requestId: request.id,
          status: request.status,
          command: request.command,
          expiresAtMs: request.expiresAtMs,
        },
        undefined,
      );
    },

    /**
     * Cancel a pending 2FA request.
     */
    "2fa.cancel": async ({ params, respond }) => {
      const manager = getTwoFactorAuthManager();
      if (!manager) {
        respond(
          false,
          undefined,
          errorShape(ErrorCodes.UNAVAILABLE, "2FA not initialized"),
        );
        return;
      }

      const p = params as { requestId?: string };
      
      if (!p.requestId || typeof p.requestId !== "string") {
        respond(
          false,
          undefined,
          errorShape(ErrorCodes.INVALID_REQUEST, "requestId is required"),
        );
        return;
      }

      const cancelled = manager.cancel(p.requestId);
      
      if (!cancelled) {
        respond(
          false,
          undefined,
          errorShape(ErrorCodes.INVALID_REQUEST, "Request not found or already resolved"),
        );
        return;
      }

      respond(true, { cancelled: true, requestId: p.requestId }, undefined);
    },
  };
}

/**
 * Format 2FA authentication message for user.
 */
export function formatTwoFactorAuthMessage(
  request: TwoFactorRequest,
  authUrl: string,
): string {
  const expiresIn = Math.ceil((request.expiresAtMs - Date.now()) / 1000 / 60);
  const mockHint =
    authUrl.includes("mock-2fa")
      ? `（当前为模拟认证，测试验证码：${request.verificationCode}）`
      : "";
  return [
    `⚠️ 检测到高危操作：\`${request.command}\``,
    `请点击链接完成二次认证：${authUrl}`,
    `完成后在此输入验证码继续执行。${mockHint}`,
    `有效期：${expiresIn} 分钟（输入 cancel 取消执行）`,
  ].join("\n");
}
