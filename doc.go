// Package auth provides a client for WayWake Auth Public OpenAPI v1.
//
// A Client may be shared by multiple goroutines. Credentials are passed per
// request, so one client can serve many employees without holding login state:
//
//   - AuthorizeURL and AuthorizePost build the browser authorization request;
//     LogoutURL builds the browser logout navigation.
//   - ExchangeCode, Refresh, ClientCredentials and ExchangeMiniProgramCode call
//     the token endpoint; RevokeToken and Introspect manage credentials.
//   - GetCurrentUser, GetCurrentPermissions, CheckCurrentPermission and
//     CheckCurrentPermissions read the authorizing employee.
//   - GetMachineIdentity and GetMachineScopes describe a machine token, and the
//     directory, IAM, event and audit calls act for the application itself.
//   - Discovery, JSONWebKeySet, GetUserInfo and the VerifyIDToken /
//     VerifyLogoutToken methods cover the OIDC half of the contract.
//
// The SDK never stores authorization transactions, tokens or permissions:
// applications must keep credentials server-side and atomically consume their
// own browser-bound authorization transactions before exchanging a code.
//
// The administrative surface reachable only from an administrator's browser
// session and the SAML browser protocol are deliberately out of scope.
package auth
