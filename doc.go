// Package auth provides a client for WayWake Auth Public OpenAPI v1.
//
// A Client may be shared by multiple goroutines. Access tokens are passed per
// request so one client can serve multiple users without sharing login state.
// AuthorizeURL builds a browser redirect; all other operations run on the
// application's backend. Applications must store and atomically consume their
// own browser-bound authorization transactions and keep credentials server-side.
package auth
