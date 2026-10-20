# PhishEyeX

PhishEyeX is a privacy-bounded, local-first email triage application. Paste raw email text to inspect only evidence observable in that text.

## What it reports

- `From`, `Return-Path`, and `Subject` headers
- SPF, DKIM, and DMARC tokens from `Authentication-Results`
- Unique HTTP(S) URLs and IPv4 addresses
- Deterministic observations for failed authentication and From/Return-Path domain differences

The application has no network analysis path, reputation service, verdict, confidence score, sandbox, attachment handling, or inferred enrichment. It does not decide whether a message is malicious. A visible 256 KiB UTF-8 input limit is enforced before parsing, and file uploads are intentionally unsupported.

## Run locally

Requires Node.js 18+ and npm.

```sh
npm install
npm run dev
```

Open the local Vite URL shown in the terminal. No API key or environment configuration is needed. All analysis runs in the browser from the pasted text.

## Quality checks

```sh
npm test
npm run typecheck
npm run build
npm run audit
```

CI runs these checks for every push and pull request. The test suite covers the deterministic engine and intake validation; it uses sanitized inline data and stores no message content.

## Safety and privacy

Use sanitized samples where possible. The application intentionally does not upload, persist, execute, decode, or render attachments. Treat extracted indicators as analyst evidence, not a threat verdict. Do not analyze live malware on production systems; use isolated, approved environments for any sandbox work.

## Repository hygiene

Sensitive files are excluded via `.gitignore`. Email samples used in tests should be sanitized of PII. No malware binaries are stored in this repository. See [SECURITY.md](./SECURITY.md) for reporting security issues.

## Disclaimer

This project is provided "as is" without warranty. The authors are not responsible for misuse or damages. It is intended for defensive cybersecurity purposes only.

## Security and vulnerabilities

Refer to [SECURITY.md](./SECURITY.md) for security reporting and vulnerability information.

## Project status

The public hostname is intentionally in maintenance mode during product improvements. The Cloudflare Worker returns HTTP 503 with `Retry-After: 86400`, `X-Robots-Tag: noindex, nofollow`, and a truthful maintenance page. The static fallback is also noindex and publishes no sitemap.

### Launch restoration path

When the product is ready for relaunch, set `MAINTENANCE_MODE` in `worker.ts` to `false`, restore the indexable metadata in `index.html`, change `public/robots.txt` to `Allow: /` with the production sitemap URL, and restore `public/sitemap.xml`. Run the complete quality checks, deploy the Worker, and verify HTTP 200, canonical, robots, and sitemap behavior before requesting indexing.


## Support

- Issues: [GitHub Issues](https://github.com/SuperMag99/phisheyex/issues)
- Maintainer: [SuperMag99](https://github.com/SuperMag99)
- LinkedIn: [mag99](https://www.linkedin.com/in/mag99/)

## License summary

This project is licensed under a Non-Commercial Attribution License. It is free for personal, educational, and research use; modifications and derivatives must credit the author; commercial use requires prior written permission; and it is provided without warranty. See [LICENSE](./LICENSE) for full details.
