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
- `Rante.Apps.Packaging` (no dependencies): checks `.rante` packages like `rante validate` and Rante's servers
  (`RantePackage`, `RantePackageReader` with `ReadFile` and `ExtractToDirectory`, `RanteManifest`,
  `RantePackagePaths`, `RanteFileTypes`, `RantePackageLimits`): a strict ZIP reader (no ZIP64, encryption or
  overlapping entries; inflation capped at the declared size; CRC-32), manifest.json rules, allowed file types and
  executable sniffing, zip-slip paths, duplicates, symbolic links and zip-bomb limits. Its path and manifest cases
  run through the JavaScript CLI in CI too.
- Versions and connect ports take ASCII digits only, like the CLI (.NET's `\d` matched every Unicode digit, and a
  non-ASCII port digit made `RanteManifest.Validate` throw).
