# magpie-codearts

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![magpie plugin](https://img.shields.io/badge/magpie-plugin-8A2BE2)](https://usemagpie.ai/docs/zh/plugins)
[![OpenCode plugin](https://img.shields.io/badge/OpenCode-plugin-blue)](https://opencode.ai)
![no dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)
![tests](https://img.shields.io/badge/tests-42%20passing-success)

[Huawei Cloud CodeArts (华为云码道 代码智能体)](https://www.huaweicloud.com/product/codearts.html)  
作为 magpie / OpenCode 的 provider 插件：用**华为云 OAuth 授权登录**接入码道的模型  
（盘古 openPangu、DeepSeek、GLM 等）。

CodeArts 的模型网关确实是 OpenAI 兼容的 Chat Completions 接口，但它**不接受 API  
Key**：请求要用临时的 AK/SK/security-token 凭据做 *SDK-HMAC-SHA256* 签名，而这些  
凭据要靠 OAuth 登录取得。Provider id 保持 `codearts`（现有登录态继续有效），显示名  
是 **CodeArts (magpie-codearts)**，用来和旧的 `yuweihao17/codearts` 插件区分。本插件完整实现了这条链路：

1.  **OAuth（PKCE + DPoP）登录**：`authorize()` 在本机 `127.0.0.1`（端口 ≥ 10000）  
    起一个回调服务器，返回华为云授权页地址给 magpie 打开；浏览器带授权码跳回后，  
    用 `code_verifier` 向 STS 换取临时凭据。登录全程是 PKCE 的，并用一把新生成的  
    ES256（P-256）DPoP 私钥给每次 token 请求签名。
2.  **SDK-HMAC-SHA256 签名**：每次模型请求都由 `loader` 的 `fetch` 用临时凭据签名，  
    和真实 IDE / CLI 的请求一致。
3.  **静默续期**：`auth.refresh` 在凭据过期前用 `refresh_token`（复用同一把  
    `code_verifier` 与 DPoP 私钥）换新凭据。
4.  **模型列表 / 用量**：登录后用签名 GET 拉取账号真实模型列表与积分套餐用量。
5.  **每日签到**：实现 magpie 的 `auth.checkin` 钩子，自动领取码道的「每日签到」  
    积分（`/v1/ops/delivery` → `claim` → `confirm`）。

## 安装

```sh
magpie plugin add cc4dogman/magpie-codearts

```

或本地开发：

```sh
magpie plugin add ./index.mjs

```

## 登录

选择 **Sign in with Huawei Cloud** 后，magpie 会先问「登录成功后打开哪个页面」：

-   **码道聊天首页**（默认）：`https://devcloud.cn-north-4.huaweicloud.com/chat/home`；
-   **官方登录结果页**：保持原来的 `portal/login?login_succeed=true`；
-   **自定义 URL…**：再输入一个 `http://` / `https://` 地址。

浏览器会打开华为云授权页；登录并在授权页确认后，浏览器会自动跳回本机的回调地址，  
插件完成登录，然后浏览器落在你选的页面。无需填写 API Key、也无需手动复制任何 token。

> 说明：magpie 的插件设置项目前只支持 Off/On 开关，所以这个选择放在登录提问里  
> （原生 `select` + 文本输入），而不是 Settings 里的下拉框。每次重新登录都可以改选。

## 使用

-   模型列表中会出现 `GLM-5.2`、`GLM-5.1`、`GLM-5`、`glm-5.3-flash`、  
    `openpangu-2.0-flash/pro`、`deepseek-v4-flash/pro`、`deepseek-v4.1-flash` 等；  
    登录后会以账号真实返回的列表为准。
-   CLI 里可用 `codearts --model codearts/GLM-5.2` 之类方式指定。

## 每日签到（自动领取积分）

插件实现了 magpie 原生的 `auth.checkin` 钩子（需要 magpie ≥ v0.1.1083）：

-   打开 **Settings → Usage → Plugins** 里 CodeArts 的 **Daily check-in** 开关后，  
    magpie 每个北京时间自然日会为每个已登录账号自动签到一次（启动 2 分钟后首查、  
    之后每 30 分钟轮询；失败 30 分钟后重试）。默认是关的。
-   账户的 Usage 卡片上可以直接 **Check in now** 手动签；结果显示在卡片里。
-   命令行 `magpie accounts checkin` / TUI 的 Usage 页也可以用。

码道的签到不是一次请求，而是一套运营活动流程：

1.  `GET /v1/ops/delivery?channel=IDE` 读活动列表，挑出 `type=USER_LOGIN` 的每日签到；
2.  可领取时 `POST /v1/ops/claim`（带 `campaignId` / `idempotentKey` / `channel`）；
3.  再 `POST /v1/ops/confirm` 把积分从「待确认」推进到账。

因此插件对 `ELIGIBLE` / `CLAIMED` / `CONFIRMED` / `CONSUMED` 四种状态分别处理：  
已领未确认（`CLAIMED`）只补 confirm，已确认则报告「今日已签到」，不会重复领取。  
Token 计费账号不在活动范围内，会返回 `ineligible`。

## 说明与已知限制

-   **模型目录**是出厂默认（上下文窗口取自码道模型卡：`GLM-5.2` = 202752、  
    `glm-5.3-flash` / `deepseek-v4-flash` / `deepseek-v4-pro` = 1048576、  
    `deepseek-v4.1-flash` = 1000000）。账号能返回实时列表时会覆盖 `id`/`name`。
-   **benefit（免费额度）模型**：`glm-5.3-flash`、`deepseek-v4.1-flash` 等需要把  
    `maas_type: benefit` 作为**参与签名**的请求头发送，否则后端返回  
    `InferHub.002002009.404 model is not registered`。插件会从 `gateway/config`  
    动态识别这批模型，冷启动时用静态兜底集合。
-   **用量**是尽力而为：读取 `snap-manager/v1/statistics/plugin` 的积分口径  
    （`usageTotalPackageCredit`），把已用比例显示为一条「total credits」窗口；  
    取不到时在用量卡片显示一条错误，不影响对话。
-   **区域 / 端点**：当前固定华为云 `cn-north-4`（与真实插件一致）。
-   **登录后跳转**：聊天首页用的是 DevCloud 自己的 Web 会话；同属华为云 IAM，通常  
    会 SSO 自动登录，但如果浏览器没有现成的 DevCloud 会话，页面可能先跳一次登录。  
    这只影响浏览器停留的页面，不影响插件已经拿到的 AK/SK 凭据。
-   本插件不内置 MCP / 中间件，仅做模型接入。
-   依赖：无（签名、PKCE、DPoP 都用运行时内置的 WebCrypto，无需 `jose` 等三方库）。

## English

**magpie-codearts** is a magpie / OpenCode provider plugin that signs you in to
[Huawei Cloud CodeArts (码道)](https://www.huaweicloud.com/product/codearts.html) with
**Huawei Cloud OAuth** (PKCE + DPoP) and exposes its models (openPangu, DeepSeek, GLM, …).

The CodeArts gateway is OpenAI-compatible Chat Completions, but it does **not** accept an API key:
every request must be signed with temporary AK/SK/security-token credentials (*SDK-HMAC-SHA256*),
and those credentials come from an OAuth sign-in. This plugin implements the whole chain —
local-callback PKCE OAuth, per-request SDK-HMAC-SHA256 signing, silent refresh — with **no runtime dependencies**.

### Install

```sh
magpie plugin add cc4dogman/magpie-codearts
```

### Sign in

Pick **Sign in with Huawei Cloud** (or run `magpie plugin login codearts`). magpie first asks
where the browser should land after the sign-in — the CodeArts chat homepage (default), the
official portal login-result page, or a custom `http(s)` URL. Your browser then opens the
Huawei Cloud consent page; after you approve, it redirects back to a local `127.0.0.1` callback,
the plugin finishes signing in, and the tab lands on the page you chose. No API key, no copy-paste.

> magpie's plugin options are Off/On switches only, so this choice is a native `select` prompt
> in the sign-in flow rather than a dropdown in Settings; it can be changed at every sign-in.

### Use

Models appear as `codearts/GLM-5.2`, `codearts/glm-5.3-flash`, `codearts/openpangu-2.0-flash`,
`codearts/deepseek-v4.1-flash`, … Verify with `magpie provider test codearts`, or pin one with
`codearts --model codearts/GLM-5.2`.

### Notes

- Region/endpoint is fixed to Huawei Cloud `cn-north-4`.
- `benefit` (free-quota) models are detected automatically and sent with a signed `maas_type: benefit` header.
- Usage is best-effort, read from the credits endpoint.
- Daily check-in: the plugin implements magpie's `auth.checkin` hook (magpie ≥ v0.1.1083).
  Turn on **Daily check-in** under **Settings → Usage → Plugins**, or press **Check in now**
  on the account's Usage card. CodeArts' check-in is an ops campaign
  (`/v1/ops/delivery` → `claim` → `confirm`), so a claimed-but-unconfirmed campaign gets
  its confirm completed on the next run rather than being reported as done.
- No MCP / gateway middleware — model access only.

## License

MIT — see [LICENSE](./LICENSE).