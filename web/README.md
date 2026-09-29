# TraceSeal web console

React 18 + TypeScript strict + Vite frontend for the M8 operator console.
The production container serves the static bundle with nginx and proxies
`/api/*` to the internal `web-api` service, so only one host port is exposed.

```bash
npm ci
npm run check
npm run dev
```

The Vite development server proxies `/api` to `http://localhost:8000` by
default. Set `WEB_API_DEV_URL` to use another development API.

No runtime asset is loaded from a CDN; fonts and icons are local dependencies.
