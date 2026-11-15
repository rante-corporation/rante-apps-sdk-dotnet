# Changelog

## 0.1.0 (unreleased)

- `RanteAppTokenVerifier`: checks Rante app access tokens as described in docs/tokens.md of rante-apps-sdk
  (signature from Rante Login's JWKS with key rotation and a refetch cooldown, `aud`, per-tenant `iss`,
  `exp` / `nbf` / `iat` with clock skew, `oid`, `idtyp`, no repeated claims), with optional tenant and scope
  requirements. Thread-safe.
- `RanteAppPrincipal`, `RanteAppsException` (with `Status` and `WwwAuthenticate`), `BearerToken`,
  `RanteApps.FrameAncestors`.
- Passes the shared conformance cases (conformance/tokens.json). net8.0 and net10.0.
- Example external app on ASP.NET Core.
