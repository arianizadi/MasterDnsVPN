# vaydns (vendored)

Copy of https://github.com/net2share/vaydns at v0.2.8 (a0ff701), with a local
patch to `client/client.go` adding `Tunnel.ListenAndServeContext` so the mobile
bridge can cancel a running tunnel. Upstream does not ship this API yet.
