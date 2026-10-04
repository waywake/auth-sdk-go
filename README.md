# WayWake Auth Go SDK

面向有后端服务的应用，封装 `auth-server` 的公网 OpenAPI v1。Go 1.22+，仅依赖标准库。
模块路径为 `github.com/waywake/auth-sdk-go`，包名为 `auth`。

## 接口范围

SDK 覆盖公开 OpenAPI v1 全部 49 个后端操作（当前规范 74 个操作，排除 19 个管理端操作、
4 个 SAML 浏览器协议操作与 2 个等价别名）。

| SDK 方法 | 服务端接口 | 身份 / scope |
| --- | --- | --- |
| `AuthorizeURL` / `AuthorizePost` / `NewAuthorization` | `GET`/`POST /openapi/v1/oauth/authorize` | 浏览器登录态 + S256 PKCE |
| `ExchangeCode` | `POST /openapi/v1/oauth/token` | `authorization_code` |
| `Refresh` | 同上 | `refresh_token`（持续授权） |
| `ClientCredentials` | 同上 | `client_credentials`（机器身份） |
| `ExchangeMiniProgramCode` | 同上 | 企业微信小程序 grant |
| `RevokeToken` / `Introspect` | `/oauth/revoke`、`/oauth/introspect` | 客户端凭据 |
| `LogoutURL` | `GET /openapi/v1/oauth/logout` | 浏览器会话 + `id_token_hint` |
| `Discovery` / `JSONWebKeySet` | OIDC 发现文档、`/.well-known/jwks.json` | 无（公开文档） |
| `GetUserInfo` | `GET /openapi/v1/userinfo` | Bearer + `openid` |
| `VerifyIDToken` / `VerifyLogoutToken` | 本地校验 | RS256 公钥验签 |
| `GetCurrentUser` | `GET /openapi/v1/me` | Bearer + `profile:read` |
| `GetCurrentPermissions` | `GET /openapi/v1/me/permissions` | Bearer + `permissions:read` |
| `CheckCurrentPermission` / `CheckCurrentPermissions` | `/me/permissions/check`、`check-batch` | Bearer + `permissions:check` |
| `GetMachineIdentity` / `GetMachineScopes` | `/machine/me`、`/machine/me/permissions` | 机器 token（无需 scope） |
| `ListDirectoryUsers` / `GetDirectoryUser` / `ListDirectoryUserDepartments` / `ListDirectoryUserGroups` | `/directory/users*` | 机器 token + `directory:read` |
| `ListDirectoryDepartments` / `ListDirectoryDepartmentMembers` / `ListDirectoryGroups` / `ListDirectoryGroupMembers` | `/directory/*` | 机器 token + `directory:read` |
| `LookupDirectoryExternalIdentities` / `ListDirectoryEmployeeExternalIdentities` | `/directory/external-identities/lookup`、`/directory/users/external-identities` | 机器 token + `directory:read` |
| `GetEmployeeLeave` | `/leave/users/{id}` | 机器 token + `leave:read` |
| `ListStores` / `GetStore` / `LookupExternalStores` | `/stores*` | 机器 token + `stores:read` |
| `GetStoreReceivingAddress` | `/stores/{id}/receiving-address` | `stores:read` + `stores:delivery:read` |
| `GetStoreEmployees` / `GetEmployeeStores` | `/stores/{id}/employees`、`/directory/users/{id}/stores` | `stores:read` + `stores:members:read` + `directory:read` |
| `ListAppRoles` / `CreateAppRole` / `DeleteAppRole` | `/iam/roles*` | `iam:read` / `iam:write` |
| `ListAppPermissions` / `CreateAppPermission` / `UpdateAppPermission` / `DeleteAppPermission` | `/iam/permissions*` | `iam:read` / `iam:write` |
| `LinkRolePermission` / `UnlinkRolePermission` | `/iam/roles/{id}/permissions*` | `iam:write` |
| `GrantUserRole` / `RevokeUserRole` / `GrantGroupRole` / `RevokeGroupRole` | `/iam/users|groups/{id}/roles*` | `iam:write` |
| `GetUserPermissions` | `GET /openapi/v1/iam/users/{id}/permissions` | `iam:read` |
| `PullEvents` | `GET /openapi/v1/events` | 机器 token + `events:read` |
| `ListAuditEvents` / `ReadAuditUsage` | `/openapi/v1/audit/*` | 机器 token + `audit:read` |

不在范围内：管理端（`/api/openapi/v1/admin/*`、`/admin/api/apps/{id}/saml`）只接受管理员浏览器会话
与 CSRF 保护，SAML 2.0（`/saml/*`）是依赖方用户与部署之间的浏览器协议，两者都不使用应用凭据。
`POST /openapi/v1/userinfo` 与 `/openapi/v1/.well-known/openid-configuration` 是等价别名，SDK 固定使用
GET 与标准发现地址。契约测试会逐项核对这份名单：服务端新增操作若既未被 SDK 调用、也不在排除表里，
测试直接失败。

## 引入

在调用方的 Go module 目录安装当前稳定版：

```sh
go get github.com/waywake/auth-sdk-go@v1.3.0
```

后续升级可使用 `go get github.com/waywake/auth-sdk-go@latest`，`go.mod` 会记录选定版本。
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
`ClientID` 使用应用数字 ID。Secret 使用应用详情「凭据与 OpenAPI」签发的独立 `oas_` 密钥，
不能使用旧 `apps.secret`。仅构造授权 URL、读取 OIDC 公开文档或调用 Bearer 资源接口时可省略 Secret；
兑换、刷新、撤销和自省必须配置。

`TokenEndpointAuth` 选择客户端认证方式，默认 `auth.TokenEndpointAuthBasic`（HTTP Basic
`APP_ID:OPENAPI_SECRET`）；`auth.TokenEndpointAuthPost` 改为在表单里发送 `client_id`/`client_secret`，
两种方式在一次请求里互斥。

客户端可并发复用，每次资源调用显式传入对应用户或机器 token。SDK 不保存登录态、不缓存 token 或权限。
应用需在服务端配置完整 HTTPS 回调地址、出口 IP 白名单和 scopes，并开启 OpenAPI。

## 两类凭据

| | 人员 token | 机器 token |
| --- | --- | --- |
| 取得方式 | 浏览器授权码 / 刷新 / 企业微信小程序 | `client_credentials` |
| 前缀 | `oat_` | `oam_` |
| 有效期 | 最长 86400 秒，持续授权会话绝对上限 72 小时 | 86400 秒 |
| 可用接口 | `/me*`、`/userinfo` | `/machine/*`、`/directory/*`、`/leave/*`、`/stores/*`、`/iam/*`、`/events`、`/audit/*` |

两套 scope 互不通用：人员 scope 为 `profile:read`、`permissions:read`、`permissions:check`、`openid`、
`profile`、`email`，机器 scope 为 `directory:read`、`leave:read`、`iam:read`、`iam:write`、`events:read`、`audit:read`、
`stores:read`、`stores:delivery:read`、`stores:members:read`。新增能力需要管理员显式授予。
SDK 会拒绝把机器 scope 传给授权请求、把人员 scope 传给 `ClientCredentials`，以及把 `oat_` 交给机器接口
（反之亦然）；真正的 scope 判定始终在服务端。

```go
token, err := client.ClientCredentials(ctx, auth.ClientCredentialsParams{
    Scopes: []auth.Scope{auth.ScopeDirectoryRead, auth.ScopeIAMRead},
})
if err != nil {
    return err
}
// 机器 token 缓存到过期前 1 分钟，不要每次调用都签发。
identity, err := client.GetMachineIdentity(ctx, token.AccessToken)
```

完整可运行的机器流程见 [examples/machine/main.go](examples/machine/main.go)：签发机器 token、读取自身身份
与 scope、翻一页目录、从游标拉一页变更流，并在游标过期（410）时提示重建快照。

```sh
export AUTH_BASE_URL=https://auth.example.com
export AUTH_CLIENT_ID=42
export AUTH_MACHINE_SCOPES="directory:read events:read"   # 可省略，默认同上
export AUTH_CURSOR=0                                       # 上次拉取得到的 next
go run ./examples/machine
```

## 完成 OAuth 登录

1. 创建授权事务并跳转：

   ```go
   tx, err := client.NewAuthorization(auth.AuthorizeParams{
       RedirectURI: "https://app.example.com/callback",
       Scopes:      []auth.Scope{auth.ScopeProfileRead, auth.ScopePermissionsRead, auth.ScopePermissionsCheck},
   })
   if err != nil {
       return err
   }
   // 将 tx.State、tx.CodeVerifier、tx.RedirectURI 保存到后端，
   // 绑定发起登录的浏览器会话，设置短期过期时间。
   // http.Redirect(w, r, tx.URL, http.StatusFound)
   ```

   需要 OIDC 时加上 `Scopes: []auth.Scope{auth.ScopeOpenID, auth.ScopeProfile}` 与 `Nonce`：

   ```go
   maxAge := int64(3600) // 只接受一小时内完成的登录；0 表示本次必须重新登录
   tx, err := client.NewAuthorization(auth.AuthorizeParams{
       RedirectURI: "https://app.example.com/callback",
       Scopes:      []auth.Scope{auth.ScopeOpenID, auth.ScopeProfile, auth.ScopeEmail},
       Nonce:       nonce, MaxAge: &maxAge, Prompt: auth.PromptLogin,
   })
   ```

   表单提交入口用 `AuthorizePost`，返回 POST 目标与表单字段；服务端 303 转到等价的 GET 请求。
   如需自行管理授权参数，可使用 `GenerateState`、`GenerateCodeVerifier`、`CodeChallenge` 与 `AuthorizeURL`
   （`NewAuthorization` 只负责生成，调用方传入 `State`/`CodeChallenge` 会被拒绝）。

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

授权码有效期 120 秒且只能消费一次。`token` 最长 86400 秒，实际读取 `ExpiresIn`。
兑换失败可能意味着授权码已经消费，SDK 不自动重试。应用停用、用户停用、配置保存或密钥轮换也会
使既有 code/token 失效。`RedirectURI` 使用原始字符串，SDK 不改写其路径或查询编码。

完整可运行的浏览器流程见 [examples/web/main.go](examples/web/main.go)，包含 Secure/HttpOnly/SameSite
Cookie、浏览器绑定、短期内存存储、恒定时间 state 校验和锁内原子消费：

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

### 持续授权与刷新

启用了 `refresh_token` 的应用在兑换时会额外拿到 `refresh_token`（`oar_`）。它属于一条
**authorization session**：绝对到期时间在员工批准那一刻固定（上限 72 小时），刷新不会延长。

```go
refreshed, err := client.Refresh(ctx, auth.RefreshParams{RefreshToken: stored})
if err != nil {
    // 会话已到期或已被撤销：重新走授权流程。
    return err
}
// 必须用新值覆盖旧值：旧 refresh token 在响应发出时即作废，
// 再次使用会让整个持续授权被撤销。
store(refreshed.RefreshToken)
```

`RefreshParams.Scopes` 可缩小本次 access token 的范围（须为原授权子集），省略则沿用原授权；
新的 refresh token 始终保留完整原授权。机器 token 永远没有 refresh 对应物。

## 用户、权限与机器身份

```go
profile, err := client.GetCurrentUser(ctx, token.AccessToken)
if err != nil {
    return err
}
fmt.Println(profile.Data.ID, profile.Data.Name, profile.RequestID)
if profile.Data.HireDate != nil {
    fmt.Println(*profile.Data.HireDate, profile.Data.HireDateSource) // YYYY-MM-DD, wecom_hr|created_at|""
}
if profile.Data.ProbationMonths != nil {
    fmt.Println(*profile.Data.ProbationMonths, profile.Data.RegularizationDate) // 0 表示无试用期
}

permissions, err := client.GetCurrentPermissions(ctx, token.AccessToken)
if err != nil {
    return err
}
fmt.Println(permissions.Data.Roles, permissions.Data.Permissions, permissions.Data.EvaluatedAt)

decision, err := client.CheckCurrentPermission(ctx, token.AccessToken, "order.read")
if err != nil {
    return err
}
if !decision.Data.Allowed {
    // 拒绝访问；合法但不存在的权限也返回 false。
}

batch, err := client.CheckCurrentPermissions(ctx, token.AccessToken, "order.read", "order.write")
// 最多 100 项，按请求顺序逐项作答，共用同一 evaluated_at 快照。
```

`/me` 只返回稳定 ID、账号名、姓名、头像与入职字段，不返回手机号、邮箱或部门；组织关系请用目录接口
（`directory:read`）。资源返回 `Response[T]`，包含 `Data` 和 `RequestID`；OAuth token 返回顶层 `Token`。
`EvaluatedAt` 是答案的计算时刻，`NextChangeAt` 是下一次计划内的授权变更时刻（无则为 `nil`）。
ID 使用 `int64`，时间使用 `time.Time`，`hire_date`/`regularization_date` 为 `YYYY-MM-DD` 字符串。
权限始终属于 token 绑定的应用和用户，接口没有任意 `user_id`/`app_id` 参数。

## 目录、IAM、事件与审计

```go
// 目录：范围由管理员配置，未配置范围时读不到任何员工。
params := auth.ListDirectoryUsersParams{
    PageParams: auth.PageParams{Limit: 200}, DepartmentID: 10, Search: "ali",
}
for {
    page, err := client.ListDirectoryUsers(ctx, machineToken, params)
    if err != nil {
        return err
    }
    // 处理 page.Data.Items。
    if page.Data.Next == 0 { // 0 表示最后一页
        break
    }
    params.After = page.Data.Next // 只有 Next 是游标，过滤条件保持不变
}

// IAM：归属只来自机器 token，请求体里出现 app_id 会被服务端拒绝。
role, err := client.CreateAppRole(ctx, machineToken, auth.RoleInput{Key: "reader", Name: "只读"})
_, err = client.LinkRolePermission(ctx, machineToken, role.Data.ID, permissionID)
expires := time.Now().Add(24 * time.Hour)
_, err = client.GrantUserRole(ctx, machineToken, userID, auth.RoleGrant{RoleID: role.Data.ID, ExpiresAt: &expires})
explanation, err := client.GetUserPermissions(ctx, machineToken, userID) // 含 sources 来源解释

// 变更流：只有 Next 是游标；事件 ID 与来源序号都不是。
events, err := client.PullEvents(ctx, machineToken, auth.PullEventsParams{
    After: cursor, Limit: 200,
    Types: []auth.EventType{auth.EventUserUpdated, auth.EventSessionRevoked},
})
for _, event := range events.Data.Events {
    // 按 event.ID 幂等处理。
}
cursor = events.Data.Next
if events.Data.HasMore && len(events.Data.Events) == 0 {
    // 过滤前的扫描页已满：即使没有事件也要继续用 Next 拉取。
}

// 审计：actor_app_id 是发起调用的应用，app_id 是该行涉及的应用，两者都属于本应用历史。
audit, err := client.ListAuditEvents(ctx, machineToken, auth.ListAuditEventsParams{
    Limit: 50, Action: "app_role_save", Outcome: auth.AuditOutcomeSuccess,
})
usage, err := client.ReadAuditUsage(ctx, machineToken, 7) // days 默认 7、上限 30；rate_limit 读不到时为 nil
```

游标早于 30 天保留窗口时 `PullEvents` 返回 `*APIError{StatusCode: 410, Code: auth.ErrorSnapshotRequired}`：
必须重建快照后从 `After: 0` 重新开始，跳过会永久漏事件。

### 外部员工身份、假期与门店

```go
// 外部员工身份使用完整四元组，批量请求最多 100 项。
identities, err := client.LookupDirectoryExternalIdentities(ctx, machineToken, []auth.ExternalIdentityKey{
    {Provider: "YOUZAN", TenantID: "tenant-1", Namespace: "SALESMAN", ExternalID: "staff-9"},
})
employees, err := client.ListDirectoryEmployeeExternalIdentities(ctx, machineToken, []int64{7, 8})

// 独立 leave:read scope；当前状态与余额来自最近一次完整同步。
leave, err := client.GetEmployeeLeave(ctx, machineToken, 7)
if err == nil && leave.Data.OnLeave != nil {
    fmt.Println(*leave.Data.OnLeave, leave.Data.SyncedAt)
}

// 门店分页使用字符串游标，最多 100 条；翻页时保持过滤条件不变。
params := auth.ListStoresParams{Limit: 100}
for {
    page, err := client.ListStores(ctx, machineToken, params)
    if err != nil { return err }
    // 处理 page.Data.Items。
    if !page.Data.HasMore { break }
    params.After = page.Data.Next
}
address, err := client.GetStoreReceivingAddress(ctx, machineToken, 101)
if err == nil && address.Data != nil {
    fmt.Println(address.Data.Address, address.Data.DeliveryTimeRequirement)
}
assignments, err := client.GetStoreEmployees(ctx, machineToken, 101)
stores, err := client.GetEmployeeStores(ctx, machineToken, 7)
bindings, err := client.LookupExternalStores(ctx, machineToken, []auth.ExternalStoreKey{
    {Provider: "YOUZAN", TenantKey: "brand-a", Namespace: "STORE", ExternalID: "9"},
})
```

外部员工身份查询按输入顺序返回；不存在、解绑或范围外的身份给出 `Binding == nil`。
按员工查询会去重并省略不可见员工，禁用但未离职员工仍可能返回 `Enabled == false`。
收到 `EventExternalIdentityChanged`（`external_identity.changed`，只含员工 ID）后，重新读取映射。

假期首次同步前 `OnLeave` 和 `SyncedAt` 为 `nil`，不能当作未休假；停用或未配置服务时返回 503。
假期时长为原始秒值，按 `unit` 为 day/hour 分别除以 86400/3600。

门店范围由独立 `store_scope` 控制，未配置时无可见门店；任职查询同时受员工目录范围限制。
未配置收货地址时 `address.Data == nil`；员工的 `PrimaryStore == nil` 仅表示没有可见主店。
任职与岗位按响应中的 `EvaluatedAt` 评估，可能禁用的员工仍保留关系；关系本身不授予 IAM 权限。
门店游标绑定应用、过滤条件与策略版本，过滤或策略变化后应从头读取。当前服务端不发布门店事件。

### webhook 验签

订阅端点的签名密钥只在管理端登记或轮换时显示一次。SDK 提供与服务端逐字节一致的验签实现：
签名覆盖 `"<timestamp>.<原始请求体>"`，因此必须先读原始字节再解析，并在容忍窗口内比较。

```go
body, _ := io.ReadAll(r.Body)
timestamp, err := strconv.ParseInt(r.Header.Get(auth.WebhookTimestampHeader), 10, 64)
if err != nil || !auth.VerifyWebhookSignature(secret, body, timestamp,
    r.Header.Get(auth.WebhookSignatureHeader), time.Now(), auth.DefaultWebhookTolerance) {
    http.Error(w, "unauthorized", http.StatusUnauthorized)
    return
}
// X-Auth-Event-Id 是稳定事件 ID，重投递不变：按它去重。
```

投递是**至少一次**：同一个事件可能再次到达，接收端必须幂等。`kind: logout` 的端点收到的是
`logout_token=` 表单，用 `VerifyLogoutToken` 校验。

## OIDC：ID Token 与后端登出

```go
document, err := client.Discovery(ctx)      // 可缓存 auth.DiscoveryCacheSeconds
keys, err := client.JSONWebKeySet(ctx)      // 按 kid 选键；未知 kid 时重新拉取一次再判失败

claims, err := keys.VerifyIDToken(token.IDToken, auth.IDTokenParams{
    Issuer: document.Issuer, ClientID: 42, Nonce: nonce, ClockSkew: 30 * time.Second,
})
if err != nil {
    return err // ErrTokenVerification；未知签名键时同时满足 errors.Is(err, auth.ErrUnknownKey)
}
// claims.Subject 是稳定员工主键，claims.AuthTime 是员工实际认证时刻。
```

`VerifyIDToken` 校验 RS256 签名、`iss` 逐字符相等、`aud` 含本应用、`exp`/`iat` 与 `nonce`；
键只来自 JWKS，绝不从 token 里取。`VerifyLogoutToken` 额外要求 `events` 含
`http://schemas.openid.net/event/backchannel-logout`、`iat` 在窗口内，并**拒绝带 `nonce` 的令牌**；
同一 `jti` 可能重复到达，按它幂等即可。

登出时把浏览器送到 `LogoutURL`；`id_token_hint` 必须匹配当前浏览器会话，回跳地址须事先登记。

## 错误处理与 HTTP 配置

```go
var apiErr *auth.APIError
if errors.As(err, &apiErr) {
    log.Printf("Auth status=%d code=%s request_id=%s",
        apiErr.StatusCode, apiErr.Code, apiErr.RequestID)
    switch apiErr.Code {
    case auth.ErrorInvalidToken:
        // 清理本地用户 token，重新发起授权。
    case auth.ErrorLoginRequired:
        // 员工不再满足登录准入：重新走授权流程。
    case auth.ErrorSnapshotRequired:
        // 事件游标早于保留窗口：重建快照后从 0 重新拉取。
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
`WWWAuthenticate`。错误码词表为 `invalid_request`、`invalid_scope`、`invalid_grant`、
`unsupported_grant_type`、`invalid_client`、`invalid_token`、`login_required`、`https_required`、
`ip_not_allowed`、`insufficient_scope`、`not_found`、`conflict`、`snapshot_required`、
`rate_limit_exceeded`、`temporarily_unavailable`。`RetryAfter` 保留原始 header，可为秒数或 HTTP 日期。
代理返回 HTML 等非标准错误时，`Code` 为空，仍保留状态和 header；错误文本不包含响应原文。
结构化响应优先使用 body 的 `request_id`，错误 body 不可用时退回 `X-Request-ID`。

本地参数错误可通过 `errors.Is(err, auth.ErrInvalidArgument)` 判断；state 错误为 `ErrStateMismatch`，
异常成功响应为 `ErrInvalidResponse`（缺少 `data`、`request_id`、`items`、`evaluated_at` 或
`allowed` 等必填字段都算），超出响应大小限制为 `ErrResponseTooLarge`，令牌校验失败为
`ErrTokenVerification`，未知签名键为 `ErrUnknownKey`。
网络错误与 context 错误保留错误链；非 200 响应的读取错误可同时通过 `errors.As` 和 `errors.Is` 检查。
响应允许 v1 新增字段，并检查关键数据是否存在，尤其区分缺失权限判断和有效 `false`。
SDK 在本地拒绝明显越界的输入（scope 词表与两类混用、普通分页 1–200／门店分页 1–100、1–100 的批量检查和身份查询、
最多 8 个事件类型过滤、权限 key 形状、`wx` + 16 位十六进制的小程序 AppID），
其余判定一律以服务端为准。

```go
client, err := auth.NewClient(auth.Config{
    BaseURL:          "https://auth.example.com",
    ClientID:         42,
    ClientSecret:     os.Getenv("AUTH_CLIENT_SECRET"),
    TokenEndpointAuth: auth.TokenEndpointAuthBasic,
    HTTPClient:       &http.Client{Timeout: 10 * time.Second},
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

基于 `../auth-server` 提交 `58e6753f65225144d7bdd182d376aeeb4ab7f6c8`（2026-10-04 核对）的：

- `docs/openapi-v1.json`：OpenAPI 3.1（info.version 1.2.0）；原样快照位于
  [docs/openapi-v1.json](docs/openapi-v1.json)。
- `docs/openapi.md`、`internal/openapi/http/*`、`internal/openapi/domain/*`：协议说明和当前行为。

本次新增 9 个后端操作：外部员工身份查询 2 个、假期查询 1 个、门店目录与任职查询 6 个。
机器 scope 扩展到 9 个，事件新增 `external_identity.changed`，收货地址包含可选送货时间要求。
既有方法保持兼容。服务端此次扩展仍沿用 `info.version: 1.2.0`，以提交与快照内容定位契约。

```sh
go test ./...
go vet ./...
go test -race -coverprofile=coverage.out ./...   # -race 需要 C 工具链（cgo）
go tool cover -func=coverage.out

# 使用相邻服务仓库的当前 OpenAPI 核对全部在范围内的操作、请求参数和编码约束。
AUTH_OPENAPI_SPEC=../auth-server/docs/openapi-v1.json go test -run '^TestOpenAPIContract$' .
```

也可执行 `make test vet contract`（`make check` 额外包含 race）。测试全部使用本地 HTTP/TLS mock
与临时 RSA 密钥，不依赖真实 Auth、MySQL、Redis 或部署密钥。契约测试读取 JSON 规范，
同时核对 scope 与事件完整词表；HTTP 测试核对鉴权和请求体，覆盖 PKCE 向量、state 边界、四类 grant、客户端认证两种方式、
分页游标、错误码、取消、响应大小、重定向、示例回调重放、webhook 验签与 ID Token/登出令牌验签。
更新服务契约后应同步快照并扩展相应类型和测试；客户端代码为手写维护。
