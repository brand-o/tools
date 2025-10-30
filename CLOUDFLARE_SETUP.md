# Cloudflare Pages Build Instructions

## To serve raw PowerShell files:

1. Copy these files to your build output directory:
   - `make.ps1` → `public/make.ps1`
   - `make.ps1` → `public/run` (same file, different name)
   - `bundle.json` → `public/bundle.json`

2. Add a `_headers` file to set correct Content-Type:

```
/run
  Content-Type: text/plain; charset=utf-8
  X-Content-Type-Options: nosniff

/make.ps1
  Content-Type: text/plain; charset=utf-8
  X-Content-Type-Options: nosniff

/bundle.json
  Content-Type: application/json; charset=utf-8
```

3. Deploy to Cloudflare Pages
