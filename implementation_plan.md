# OpenClaw 二次认证（2FA）高危操作保护实现方案

## 概述

本方案旨在为 OpenClaw 添加二次认证功能，当检测到高危操作时，暂停执行并要求用户通过外部链接进行二次认证。认证通过后获取验证码，输入验证码后 OpenClaw 验证通过方可继续执行命令。

## 现状更新（已实现与验证）

- 已实现内置 2FA 管理器（TwoFactorAuthManager），支持超时与验证码校验，并提供单例初始化与获取接口
  - 文件：`src/security/two-factor-auth.ts`
  - 支持配置：`enabled`、`timeoutSeconds`、`authBaseUrl`、`codeLength`、`mock.{enabled,authUrl,code}`
- 已在网关启动时初始化 2FA，并加载配置（含 mock）
  - 文件：`src/gateway/server.impl.ts`
  - 行为：当 `security.twoFactor.enabled` 为真时初始化；若 `security.twoFactor.mock.enabled` 为真，则使用 mock 链接与固定验证码
- 已在命令执行工具中集成高危检测与 2FA 阻断
  - 文件：`src/agents/bash-tools.exec.ts`
  - 行为：命中高危命令后，发送 2FA 提示消息并等待验证；验证通过后将 `security` 提升为 `full` 继续执行
- 已在 Discord 私聊入口增加 2FA 快速测试与验证码捕获
  - 文件：`src/discord/monitor/message-handler.process.ts`
  - 行为：私聊输入 `2fa-test` 时主动发送认证消息并等待；私聊输入形如 4–10 位字母数字的验证码时，直接匹配当前会话的待验证请求并即时反馈结果
- 已扩展配置 Schema 以支持 `security.twoFactor.mock`，并在网关初始化时读取
  - 文件：`src/config/zod-schema.ts`
  - 新增键：`security.twoFactor.mock.enabled|authUrl|code`
- 已提供网关方法用于 2FA 验证/状态查询/取消
  - 文件：`src/gateway/server-methods/two-factor-auth.ts`
  - 方法：`2fa.verify`、`2fa.status`、`2fa.cancel`；提示文案包含认证链接与有效期

备注：上述实现已在本地通过 Discord 私聊测试，mock 模式下使用验证码 `123456` 可稳定通过；认证链接建议固定为 `http://127.0.0.1:18789` 以避免 0.0.0.0 的可达性问题。

## 调研结论

### 项目能力分析

经过详细调研，**OpenClaw 项目完全具备实现二次认证功能的基础架构**：

#### 1. 现有批准机制
- **`src/infra/exec-approvals.ts`**：完整的命令审批系统
  - 支持 `deny`、`allowlist`、`full` 三种安全模式
  - 支持 `always`、`on-miss`、`off` 三种 ask 模式
  - 具备 socket 通信机制进行审批
  - 支持 agent 级别的权限配置

- **`src/gateway/exec-approval-manager.ts`**：批准流程管理器
  - `create()`: 创建待审批记录
  - `waitForDecision()`: 异步等待审批决定（带超时）
  - `resolve()`: 解决审批请求

#### 2. 命令执行钩子
- **`src/agents/bash-tools.exec.ts`**：命令执行工具
  - 已有 `approval-pending`、`approval-id`、`approval-slug` 状态
  - 支持审批超时机制（默认 120 秒）
  - 支持审批请求超时机制（默认 130 秒）

#### 3. Webhook/Hooks 系统
- **`src/gateway/hooks.ts`**：外部调用接口
  - 支持 Bearer Token 认证
  - 支持 JSON body 解析
  - 可扩展为二次认证回调接口

#### 4. 多平台集成
- Discord、Telegram、Slack、Line、Signal 等多平台支持
- 统一的消息发送机制，便于发送认证链接

---

## 实现方案

### 架构设计

```mermaid
sequenceDiagram
    participant User as 用户
    participant Bot as OpenClaw Bot
    participant 2FA as 2FA 验证服务
    participant Backend as 后端验证接口

    User->>Bot: 执行高危命令
    Bot->>Bot: 检测到高危操作
    Bot->>2FA: 生成验证请求
    2FA-->>Bot: 返回验证链接 + 请求ID
    Bot->>User: 发送验证链接
    User->>2FA: 访问链接完成认证
    2FA-->>User: 显示验证码
    User->>Bot: 输入验证码
    Bot->>Backend: 验证验证码
    Backend-->>Bot: 验证结果
    Bot->>Bot: 继续/拒绝执行命令
```

### 模块设计

#### 1. 高危操作检测器 [READY]
**文件**: `src/security/high-risk-detector.ts`

功能：
- 定义高危操作规则（命令模式匹配）
- 检测命令是否属于高危操作
- 支持可配置的规则列表

```typescript
// 高危操作示例规则
const HIGH_RISK_PATTERNS = [
  /^rm\s+(-rf?|--recursive)\s+/,        // 删除命令
  /^(sudo|doas)\s+/,                     // 提权命令
  /\bdrop\s+(database|table)\b/i,        // 数据库删除
  /^git\s+push\s+(-f|--force)/,          // 强制推送
  /^kubectl\s+delete\s+/,                // K8s 删除
  /^docker\s+(rm|rmi|system\s+prune)/,   // Docker 清理
];
```

---

#### 2. 二次认证管理器 [READY]
**文件**: `src/security/two-factor-auth.ts`

功能：
- 生成认证请求和验证码
- 管理待认证状态
- 验证用户提供的验证码

```typescript
interface TwoFactorRequest {
  id: string;
  command: string;
  createdAt: number;
  expiresAt: number;
  verificationCode: string;
  authUrl: string;
  status: 'pending' | 'verified' | 'expired' | 'rejected';
  sessionKey?: string;
  agentId?: string;
}

class TwoFactorAuthManager {
  create(request: TwoFactorRequestPayload): TwoFactorRequest;
  waitForVerification(requestId: string, timeoutMs: number): Promise<boolean>;
  verify(requestId: string, code: string): boolean;
  markVerified(requestId: string): void;
  getAuthUrl(requestId: string): string;
}
```

---

#### 3. 外部认证服务接口 [PLANNED]
**文件**: `src/security/two-factor-provider.ts`

功能：
- 定义外部认证服务接口
- 支持多种认证提供商（可配置）
- HTTP 请求验证

```typescript
interface TwoFactorProvider {
  name: string;
  generateAuthUrl(requestId: string, metadata: object): string;
  verifyCode(requestId: string, code: string): Promise<boolean>;
}

// 内置提供商：使用 OpenClaw Gateway 或自托管服务
class GatewayTwoFactorProvider implements TwoFactorProvider {
  // 通过 Gateway hooks 接收回调
}

// 外部提供商：对接第三方服务
class ExternalTwoFactorProvider implements TwoFactorProvider {
  // 调用配置的外部 HTTP 接口
}

```

---

#### 4. 配置扩展 [UPDATED]
**文件**: `src/config/config.ts`

新增配置项：
```yaml
security:
  twoFactor:
    enabled: true
    timeoutSeconds: 300
    authBaseUrl: "http://127.0.0.1:18789"
    codeLength: 6
    mock:
      enabled: true
      authUrl: "https://mock-2fa.example/verify?from=openclaw"
      code: "123456"
    highRiskCommands:
      enabled: true
      disabledPatternIds: []
      customPatterns: []
```

---

#### 5. 命令执行集成 [READY]
**文件**: `src/agents/bash-tools.exec.ts`

修改 `createExecTool()` 函数，在命令执行前添加二次认证检查：

```typescript
// 在执行命令前检查
if (isHighRiskCommand(command) && twoFactorAuthEnabled) {
  const authRequest = await twoFactorManager.create({
    command,
    sessionKey,
    agentId,
  });
  
  // 发送认证链接给用户
  await notifyUserForAuth(authRequest);
  
  // 等待验证
  const verified = await twoFactorManager.waitForVerification(
    authRequest.id,
    timeoutMs
  );
  
  if (!verified) {
    return { status: 'rejected', reason: '2FA verification failed or expired' };
  }
}
// 继续执行命令
```

---

#### 6. Gateway 认证端点 [READY]
**文件**: `src/gateway/server-methods/two-factor-auth.ts`

新增 Gateway API 端点：

```typescript
// POST /api/2fa/callback
// 用户完成外部认证后，服务回调此接口
interface TwoFactorCallback {
  requestId: string;
  success: boolean;
  code?: string;
}

// GET /api/2fa/status/:requestId
// 查询认证状态

// POST /api/2fa/verify
// 验证用户输入的验证码
interface TwoFactorVerifyRequest {
  requestId: string;
  code: string;
}
```

---

#### 7. 消息通道集成 [UPDATED]
**文件**: 各平台 handler（Discord/Telegram/Slack 等）

在检测到高危操作时，通过对应平台发送认证链接消息：

```typescript
// 通用认证消息格式
const authMessage = {
  text: `⚠️ 检测到高危操作：\`${command}\`\n\n` +
        `请点击链接完成二次认证：${authUrl}\n` +
        `认证完成后，请输入验证码继续执行。\n` +
        `有效期：5分钟`,
  buttons: [
    { label: "去认证", url: authUrl },
    { label: "取消执行", action: "cancel" }
  ]
};
```

---

### 文件变更清单

| 操作 | 文件路径 | 说明 |
|------|---------|------|
| [READY] | `src/security/high-risk-detector.ts` | 高危操作检测器 |
| [READY] | `src/security/two-factor-auth.ts` | 二次认证管理器（含 mock 支持） |
| [PLANNED] | `src/security/two-factor-provider.ts` | 认证服务提供商接口（外部 2FA） |
| [READY] | `src/gateway/server-methods/two-factor-auth.ts` | Gateway 2FA API |
| [UPDATED] | `src/config/zod-schema.ts` | 扩展 `security.twoFactor.mock` |
| [READY] | `src/gateway/server.impl.ts` | 初始化 2FA（含 mock） |
| [READY] | `src/agents/bash-tools.exec.ts` | 集成 2FA 检查与执行提升 |
| [UPDATED] | `src/discord/monitor/message-handler.process.ts` | 私聊 2FA 测试与验证码捕获 |
| [PLANNED] | `src/security/two-factor-auth.test.ts` | 单元测试 |
| [PLANNED] | `src/security/trusted-devices.ts` | 记住设备管理器 |

---

#### 8. 记住设备功能 [PLANNED]
**文件**: `src/security/trusted-devices.ts`

功能：
- 基于设备/会话指纹生成唯一标识
- 存储信任设备列表（带过期时间）
- 检查当前设备是否已信任

```typescript
interface TrustedDevice {
  id: string;
  fingerprint: string;       // 设备/会话指纹
  userId: string;            // 用户标识
  channelId: string;         // 来源平台
  trustedAt: number;         // 信任时间
  expiresAt: number;         // 过期时间
  lastUsedAt: number;        // 最后使用时间
}

class TrustedDeviceManager {
  // 生成设备指纹（基于 sessionKey + channelId + 用户信息）
  generateFingerprint(context: AuthContext): string;
  
  // 添加信任设备
  addTrustedDevice(fingerprint: string, daysValid: number): TrustedDevice;
  
  // 检查设备是否已信任
  isTrusted(fingerprint: string): boolean;
  
  // 移除信任（用户主动撤销）
  revokeTrust(deviceId: string): void;
  
  // 清理过期设备
  cleanExpired(): void;
  
  // 列出用户所有信任设备
  listDevices(userId: string): TrustedDevice[];
}
```

**配置扩展**（补充到 `config.yaml`）：
```yaml
security:
  twoFactorAuth:
    # ... 其他配置 ...
    rememberDevice:
      enabled: true
      defaultDays: 30        # 默认信任天数
      maxDays: 90            # 最大信任天数
      allowUserChoice: true  # 允许用户选择是否记住
```

**认证流程更新**：
```typescript
// 检查是否已信任设备
const fingerprint = trustedDeviceManager.generateFingerprint(context);
if (trustedDeviceManager.isTrusted(fingerprint)) {
  // 跳过 2FA，直接执行
  return executeCommand(command);
}

// 未信任，执行正常 2FA 流程
const verified = await twoFactorManager.waitForVerification(...);

if (verified && userChoseRemember) {
  trustedDeviceManager.addTrusted(fingerprint, rememberDays);
}
```

**用户交互更新**：
```typescript
const authMessage = {
  text: `⚠️ 检测到高危操作：\`${command}\`\n\n` +
        `请点击链接完成二次认证：${authUrl}\n` +
        `有效期：5分钟`,
  buttons: [
    { label: "去认证", url: authUrl },
    { label: "取消执行", action: "cancel" }
  ],
  options: [
    { label: "记住此设备 30 天", value: "remember_30" },
    { label: "本次不记住", value: "no_remember" }
  ]
};
```

## 验证计划

### 单元测试

1. **高危操作检测测试** [PLANNED]
   ```bash
   pnpm test -- --grep "high-risk-detector"
   ```
   - 测试各种高危命令模式匹配
   - 测试安全命令不触发检测
   - 测试自定义规则配置

2. **二次认证管理器测试** [PLANNED]
   ```bash
   pnpm test -- --grep "two-factor-auth"
   ```
   - 测试认证请求创建
   - 测试验证码生成和验证
   - 测试超时处理
   - 测试并发请求

### 集成测试

1. **Gateway API 测试** [PLANNED]
   ```bash
   pnpm test:e2e -- --grep "two-factor"
   ```
   - 测试回调端点
   - 测试验证端点
   - 测试状态查询

### 手动测试

1. **配置启用 2FA（已支持）**
   - 在 `openclaw.json` 中启用：
     - `security.twoFactor.enabled: true`
     - `security.twoFactor.authBaseUrl: "http://127.0.0.1:18789"`
     - `security.twoFactor.mock.enabled: true`
     - `security.twoFactor.mock.authUrl: "https://mock-2fa.example/verify?from=openclaw"`
     - `security.twoFactor.mock.code: "123456"`

2. **触发高危操作**
   - 通过 Discord/Telegram 发送 `rm -rf /tmp/test` 命令
   - 确认收到认证链接消息

3. **完成认证流程**
   - 点击认证链接
   - 获取验证码
   - 输入验证码（mock 模式为 `123456`）
   - 确认命令继续执行

4. **测试超时场景**
   - 不完成认证，等待超时
   - 确认命令被取消

---

## 关键设计决策

### 1. 验证码方式 vs 即时回调

**选择：验证码方式**

理由：
- 跨平台兼容性好：所有平台都支持文本输入
- 用户控制：用户可以选择何时输入验证码
- 安全性：即使链接被截获，没有验证码也无法继续

### 2. 外部服务 vs 内置服务

**选择：支持两种模式**

- **内置模式**（Gateway）：适合自托管部署，无需外部依赖
- **外部模式**：对接企业 2FA 系统（如 Okta、Duo）

### 3. 高危操作定义

**选择：可配置规则 + 内置默认规则**

- 提供合理的默认规则覆盖常见高危操作
- 用户可自定义添加或禁用规则

---

## 下一步

> [!IMPORTANT]
> 请基于当前“已实现/规划”状态确认是否继续推进剩余模块（外部提供商、记住设备、测试套件）。

**已确认的设计选项**：
- ✅ 支持外部 2FA 服务（Okta、Duo Security）  
- ✅ 高危操作规则可配置
- ✅ 验证码有效期 5 分钟
- ✅ 记住设备功能（默认 30 天，最长 90 天）

---

## 运行注意与故障排查（新增）

- Discord 启动失败（Failed to resolve Discord application id）
  - 原因：使用 Bot Token 调用 `/oauth2/applications/@me` 未返回应用信息（令牌错误/撤销/超时）
  - 修复：更新为最新 Bot Token；必要时延长解析超时或在失败时降级为监听模式
- 列目录命令默认被允许列表拒绝
  - 建议：为 Windows 添加 `tools.exec.safeBins: ["powershell","pwsh"]` 放行无路径参数用法；或将 `powershell.exe/pwsh.exe/cmd.exe` 加入 allowlist
- 认证链接主机
  - 建议：固定为 `http://127.0.0.1:18789`，避免 0.0.0.0 浏览器不可达
