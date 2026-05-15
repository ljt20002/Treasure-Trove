# GitHub Pages + Cloudflare Workers KV 个人密钥库

这是一个单用户、端到端加密的个人密钥库 Demo。前端放在 GitHub Pages，Cloudflare Worker 只负责读写一份加密后的 `vault:state`，KV 和 Worker 都看不到主密钥和明文密钥。

## 目录

- `docs/`: GitHub Pages 静态页面。
- `src/index.ts`: Cloudflare Worker API。
- `wrangler.jsonc`: Worker 和 KV 绑定配置。

## KV 结构

KV 只保存一个 key：

```text
vault:state
```

这个 value 是整份密钥库的加密 envelope。每个应用不会拆成单独的 KV 记录，Cloudflare 侧也看不到应用名、账号和密钥明文。

浏览器解密后的明文结构只保留必要字段：

```json
{
  "vaultVersion": 1,
  "writeToken": "random-32-bytes-base64url",
  "entries": [
    {
      "id": "uuid",
      "app": "GitHub",
      "credentials": [
        {
          "id": "uuid",
          "account": "example",
          "secret": "ghp_xxx"
        }
      ],
      "updatedAt": "2026-05-15T12:00:00.000Z"
    }
  ]
}
```

## 本地运行

先安装依赖：

```bash
npm install
```

启动 Worker API。默认会连接真实 Cloudflare KV：

```bash
npm run dev:api
```

这个命令使用 `wrangler dev --remote`。`wrangler.jsonc` 里把 `preview_id` 显式设成和 `id` 相同，所以本地开发会读写真实 Cloudflare KV namespace。

启动静态页面：

```bash
npm run dev:web
```

打开 `http://localhost:4173`，把页面里的 Worker API 地址填成：

```text
http://localhost:8787
```

如果你想临时只用本地模拟 KV，不碰真实数据，可以改用：

```bash
npm run dev:api:local
```

## 样式边界

`docs/styles.css` 按三段维护：

- 公共样式：颜色、字体、按钮、输入框、卡片等不随设备变化的基础样式。
- `@media (min-width: 821px)`：PC 布局，只改桌面端结构和尺寸。
- `@media (max-width: 820px)`：移动端布局，只改手机和平板窄屏结构和尺寸。

后续只调整某一端样式时，优先改对应 media block，避免误伤另一端。

## 部署

1. 当前 `wrangler.jsonc` 已配置：
   - Worker 名称：`cangbaoge-api`
   - GitHub Pages origin：`https://ljt20002.github.io`
   - KV namespace：`bf69a17eac6f4f2284ba78970f29437f`

2. 推荐设置首次初始化保护：

```bash
npx wrangler secret put SETUP_TOKEN
```

首次在网页创建密钥库时，把这个值填到 `Setup Token`。初始化完成后，后续保存只依赖加密 vault 里的 `writeToken`。

3. 部署 Worker：

```bash
npm run deploy
```

4. GitHub Pages 选择 `main` 分支的 `docs/` 目录作为发布源。

5. 打开 GitHub Pages 页面，把 Worker API 地址填成部署后的 Workers 地址，例如：

```text
https://cangbaoge-api.1027900565.workers.dev
```

## API

- `GET /api/health`: 检查 Worker 和 KV 是否可用。
- `GET /api/vault`: 获取加密后的 vault envelope。
- `POST /api/setup`: 首次创建 vault，仅在 `vault:state` 不存在时允许。
- `PUT /api/vault`: 更新 vault，需要 `Authorization: Bearer <writeToken>` 和 `If-Match: <rev>`。

## 保存

- 修改应用、账号或密钥后会进入 `待保存` 状态。
- 页面不会定时自动写入 KV。
- 条目编辑区的 `保存` 会写入 KV，并重新拉取最新密文更新界面。
- 保存失败时仍保留 `待保存` 状态，可以继续修改后再次保存。
- 如果本次进入系统后改过内容且仍处于 `待保存`，离开页面时会提醒先保存。
- 解锁时只做本地兼容处理，不会因为历史结构差异自动写入 KV。

## 重置系统

解锁后可以点击 `重置系统`：

- 必须输入 `RESET` 确认。
- 必须输入两次新的主密钥。
- 成功后会清空所有密钥条目。
- 成功后会重新生成 `writeToken`，旧主密钥和旧写入凭证都会失效。
- 这是不可恢复操作，执行前需要确认已有数据不再需要。

## 主密钥强度提示

首次初始化和重置系统时，页面会在浏览器本地估算主密钥强度：

- 不会把主密钥发给 Worker。
- 估算项包括长度、字符空间、重复/顺序/常见格式惩罚。
- 攻破时间按 `PBKDF2-HMAC-SHA256` 的 `600,000` 次迭代，以及离线攻击 `100,000` 次/秒做量级估算。
- 这是提示，不是安全保证；真实风险还包括密码泄露库、设备被控、社工和弱随机来源。

## 安全边界

- 主密钥只在浏览器内存里使用，不写入 `localStorage`。
- Worker 只存密文 envelope 和 `writeToken` 的 SHA-256 hash。
- KV 只保存一个 key：`vault:state`。
- 前端不使用第三方 CDN 脚本。
- KV 对同一个 key 有 `1 write/sec` 限制，适合个人低频修改。
- 主密钥丢失后无法恢复 vault。
