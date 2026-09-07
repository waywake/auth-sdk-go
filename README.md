# WayWake Auth Go SDK

面向有后端服务的应用，封装 `auth-server` 的公网 OpenAPI v1。Go 1.22+，仅依赖标准库。
模块路径为 `github.com/waywake/auth-sdk-go`，包名为 `auth`。

## 接口范围

| SDK 方法 | 服务端接口 | 身份 / scope |
| --- | --- | --- |
| `AuthorizeURL` / `NewAuthorization` | `GET /openapi/v1/oauth/authorize` | 浏览器登录态 + S256 PKCE；SDK 生成 URL |
| `ExchangeCode` | `POST /openapi/v1/oauth/token` | Basic `APP_ID:OPENAPI_SECRET` |
| `RevokeToken` | `POST /openapi/v1/oauth/revoke` | Basic `APP_ID:OPENAPI_SECRET` |
| `GetCurrentUser` | `GET /openapi/v1/me` | Bearer + `profile:read` |
| `GetCurrentPermissions` | `GET /openapi/v1/me/permissions` | Bearer + `permissions:read` |
| `CheckCurrentPermission` | `POST /openapi/v1/me/permissions/check` | Bearer + `permissions:check` |

范围覆盖当前 OpenAPI 的全部 6 个操作。管理接口、旧 JSON-RPC、企业微信消息/通讯录不属于本 SDK。
服务端尚未提供 refresh token、client_credentials 和 OIDC ID token。

## 引入

仓库为私有仓库，调用方需要 GitHub 仓库读取权限及可用的 Git 凭据。
将 `github.com/waywake/*` 加入现有 `GOPRIVATE` 配置后，在调用方的 Go module 目录运行：

```sh
go get github.com/waywake/auth-sdk-go@latest
```

尚未发布版本 tag 时，`@latest` 使用默认分支对应的伪版本；`go.mod` 会记录该版本。
本地联调也可通过 replace 使用：

```sh
# 在调用方的 Go module 目录运行；替换为 SDK 的实际路径。
go mod edit -require=github.com/waywake/auth-sdk-go@v0.0.0
go mod edit -replace=github.com/waywake/auth-sdk-go=/absolute/path/to/auth-sdk-go
```

添加 SDK import 后执行 `go mod tidy`。联调结束后移除本地 replace，并选择需要使用的远程版本。

```go
import auth "github.com/waywake/auth-sdk-go"
```

## 创建客户端

```go
client, err := auth.NewClient(auth.Config{
    BaseURL:      "https://auth.example.com",
    ClientID:     42,
    ClientSecret: os.Getenv("AUTH_CLIENT_SECRET"),
})
if err != nil {
    return err
}
```

`BaseURL` 填部署 origin，可带端口和末尾 `/`，不附加 `/openapi/v1`、路径、query 或 fragment。
`ClientID` 使用应用数字 ID。Secret 使用应用详情「回调与 OpenAPI」生成的独立 `oas_` 密钥，
不能使用旧 `apps.secret`。仅构造授权 URL 或调用 Bearer 资源接口时可省略 Secret；兑换和撤销必须配置。

客户端可并发复用，每次资源调用显式传入对应用户 token。SDK 不保存登录态、不缓存 token 或权限。
应用需在服务端配置完整 HTTPS 回调地址、出口 IP 白名单和 scopes，并开启 OpenAPI。

## 完成 OAuth 登录

1. 创建授权事务并跳转：

   ```go
   tx, err := client.NewAuthorization(
       "https://app.example.com/callback",
       auth.ScopeProfileRead,
       auth.ScopePermissionsRead,
       auth.ScopePermissionsCheck,
   )
   if err != nil {
       return err
   }
   // 将 tx.State、tx.CodeVerifier、tx.RedirectURI 保存到后端，
   // 绑定发起登录的浏览器会话，设置短期过期时间。
   // http.Redirect(w, r, tx.URL, http.StatusFound)
   ```

2. 回调中拒绝缺失、重复或无法解析的 `state`/`code`；查找当前浏览器对应的事务，检查过期，
   用 `auth.VerifyState(tx.State, receivedState)` 比较 state，并**原子消费事务**。
   state 校验和消费成功后才兑换 code。`VerifyState` 本身不负责存储、过期和防重放。

   ```go
   // tx 来自已成功校验并原子消费的浏览器事务。
   token, err := client.ExchangeCode(ctx, auth.ExchangeCodeParams{
       Code:         receivedCode,
       RedirectURI:  tx.RedirectURI,
       CodeVerifier: tx.CodeVerifier,
   })
   if err != nil {
       return err
   }
   // token.AccessToken 仅保存在后端；ExpiresIn 单位为秒。
   ```

3. 使用对应用户的 token 调用资源接口。

授权码有效期 120 秒且只能消费一次。token 当前有效 900 秒，实际读取 `ExpiresIn`；到期后重新授权。
兑换失败可能意味着授权码已经消费，SDK 不自动重试。应用停用、用户停用、配置保存或 Secret 轮换也会
使既有 code/token 失效。`RedirectURI` 使用原始字符串，SDK 不改写其路径或查询编码。

如需自行管理授权参数，可使用 `GenerateState`、`GenerateCodeVerifier`、`CodeChallenge` 和 `AuthorizeURL`。
state 与 verifier 各使用 32 个随机字节；S256 challenge 按 RFC 7636 计算。

完整可运行的浏览器流程见 [examples/web/main.go](examples/web/main.go)，包含 Secure/HttpOnly/SameSite Cookie、
浏览器绑定、短期内存存储、恒定时间 state 校验和锁内原子消费：

```sh
export AUTH_BASE_URL=https://auth.example.com
export AUTH_CLIENT_ID=42
export AUTH_REDIRECT_URI=https://app.example.com/callback
# 通过环境或 secret 管理工具注入 AUTH_CLIENT_SECRET。
go run ./examples/web
```

示例默认监听 `127.0.0.1:8080`，通过 HTTPS 反向代理访问 `https://app.example.com/login`。
预先登记 `/callback` 完整回调和 `profile:read` scope，并放行应用后端出口 IP。
可通过 `LISTEN_ADDR` 修改监听地址。示例登录成功只展示用户资料，不建立业务会话；
内存事务仅适用于单进程演示，生产多实例请替换为支持原子消费的共享存储。

## 用户与权限

```go
profile, err := client.GetCurrentUser(ctx, token.AccessToken)
if err != nil {
    return err
}
fmt.Println(profile.Data.ID, profile.Data.Name, profile.RequestID)
if profile.Data.HireDate != nil {
    fmt.Println(*profile.Data.HireDate) // YYYY-MM-DD
}
for _, dept := range profile.Data.Departments {
    fmt.Println(dept.ID, dept.ParentID, dept.Name, dept.Order)
}

permissions, err := client.GetCurrentPermissions(ctx, token.AccessToken)
if err != nil {
    return err
}
fmt.Println(permissions.Data.Roles, permissions.Data.Permissions)

decision, err := client.CheckCurrentPermission(ctx, token.AccessToken, "order.read")
if err != nil {
    return err
}
if !decision.Data.Allowed {
    // 拒绝访问；合法但不存在的权限也返回 false。
}
```

资源返回 `Response[T]`，包含 `Data` 和 `RequestID`；OAuth token 返回顶层 `Token`。
ID 使用 `int64`。权限始终属于 token 绑定的应用和用户，接口没有任意 `user_id`/`app_id` 参数。

```go
err := client.RevokeToken(ctx, auth.RevokeTokenParams{
    Token:         token.AccessToken,
    TokenTypeHint: "access_token", // 可省略
})
```

撤销成功返回 `nil`；未知或其他应用的 token 也返回成功，和服务端的幂等语义一致。

## 错误处理与 HTTP 配置

```go
var apiErr *auth.APIError
if errors.As(err, &apiErr) {
    log.Printf("Auth status=%d code=%s request_id=%s",
        apiErr.StatusCode, apiErr.Code, apiErr.RequestID)
    switch apiErr.Code {
    case auth.ErrorInvalidToken:
        // 清理本地用户 token，重新发起授权。
    case auth.ErrorRateLimitExceeded:
        // 结合 apiErr.RetryAfter 决定稍后何时调用。
    case auth.ErrorInsufficientScope:
        // 核对应用配置和本次授权请求的 scopes。
    }
}
if errors.Is(err, context.DeadlineExceeded) {
    // 超时，按业务需求处理。
}
```

所有非 200 响应均返回 `*APIError`，保留 `StatusCode`、`Code`、`RequestID`、`RetryAfter` 和
`WWWAuthenticate`。`RetryAfter` 保留原始 header，可为秒数或 HTTP 日期。代理返回 HTML 等非标准错误时，
`Code` 为空，仍保留状态和 header；错误文本不包含响应原文。结构化响应优先使用 body 的 `request_id`，
错误 body 不可用时退回 `X-Request-ID`。

本地参数错误可通过 `errors.Is(err, auth.ErrInvalidArgument)` 判断；state 错误为 `ErrStateMismatch`，
异常成功响应为 `ErrInvalidResponse`，超出响应大小限制为 `ErrResponseTooLarge`。
网络错误与 context 错误保留错误链；非 200 响应的读取错误可同时通过 `errors.As` 和 `errors.Is` 检查。
响应允许 v1 新增字段，并检查关键数据是否存在，尤其区分缺失权限判断和有效 `false`。

```go
client, err := auth.NewClient(auth.Config{
    BaseURL:      "https://auth.example.com",
    ClientID:     42,
    ClientSecret: os.Getenv("AUTH_CLIENT_SECRET"),
    HTTPClient: &http.Client{Timeout: 10 * time.Second},
    MaxResponseBytes: 8 << 20,
})
```

默认超时 15 秒，响应上限 4 MiB。注入 `HTTPClient` 时保留其 Transport 和 Timeout，
其中零 Timeout 表示由调用方通过 context 控制时限。SDK 复制客户端、禁用重定向、移除 Cookie Jar，
不修改调用方原对象，避免将带凭证的请求转发到其他地址。自定义 Transport 的日志、重试和并发行为由调用方负责。
所有网络接口接收 `context.Context`，SDK 不做自动重试。

默认只允许 HTTPS；单元测试或本地 HTTP mock 可显式设置 `AllowInsecureHTTP: true`。
该选项只影响 SDK BaseURL，不放宽服务端 HTTPS 策略或授权回调的 HTTPS 要求。

## 契约与验证

基于 `../auth-server` 提交 `e8ed8053c717f50aec3ef32b8238d469ba62fd3c`（2026-09-07 核对）的：

- `docs/openapi-v1.json`：OpenAPI 3.1；原样快照位于 [docs/openapi-v1.json](docs/openapi-v1.json)。
- `docs/openapi.md`、`internal/openapi/http.go`、`internal/openapi/model.go`：协议说明和当前行为。

上游 JSON 的 `Profile` 暂未列出 `hire_date` / `hire_date_source` 和 `departments`，上游 Markdown、
服务端组织模型已经提供。SDK 兼容二者：`HireDate *string` 接收 `null` 或缺失值，`HireDateSource` 接收
`wecom_hr`、`created_at` 或空值；`Departments []Department` 接收 `null` 或缺失值，元素为
`{id, parent_id, name, order}`，与服务端 IAM 部门模型一致，用户与部门为多对多，`parent_id` 为 0 表示
根部门，`order` 为显示排序。上游权限检查还会校验 IAM key 语法，SDK 不代替服务端权限策略。本次未修改 auth-server。

```sh
go test ./...
go vet ./...
go test -race -coverprofile=coverage.out ./...
go tool cover -func=coverage.out

# 使用相邻服务仓库的当前 OpenAPI 核对 6 个操作、请求参数和编码约束。
AUTH_OPENAPI_SPEC=../auth-server/docs/openapi-v1.json go test -run '^TestOpenAPIContract$' .
```

也可执行 `make check`。测试全部使用本地 HTTP/TLS mock，不依赖真实 Auth、MySQL、Redis 或密钥。
契约测试读取 JSON 规范，HTTP 测试核对鉴权和请求体，覆盖 PKCE 向量、state 边界、并发、错误、取消、
响应大小、重定向及示例回调重放。更新服务契约后应同步快照并扩展相应类型和测试；客户端代码为手写维护。
