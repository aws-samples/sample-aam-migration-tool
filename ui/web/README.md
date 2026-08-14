# Truffle web UI (Cloudscape + React + Vite)

The console UI, built with the [Cloudscape Design System](https://cloudscape.design/)
— the same design system the AWS Console uses.

## Develop

Run the Flask API in one terminal (from `ui/`):

```bash
python3 app.py        # http://127.0.0.1:5000
```

Run the Vite dev server in another (from `ui/web/`):

```bash
npm install
npm run dev           # http://127.0.0.1:5173  (proxies /api to Flask)
```

## Build (served by Flask)

```bash
npm run build         # emits web/dist/
```

Then `python3 app.py` serves the built app from `web/dist` at
http://127.0.0.1:5000.

## Structure

```
src/
├── main.tsx                 # entry; loads Cloudscape global styles
├── App.tsx                  # TopNavigation + AppLayout + SideNavigation shell
├── api/client.ts            # typed fetch wrapper for /api
├── components/
│   └── ProfileSelect.tsx    # shared AWS-profile pickers
└── pages/
    ├── PolicyAnalysis.tsx   # WIRED to the scanner
    ├── IamFederation.tsx    # skeleton workflow
    └── Idc.tsx              # skeleton workflow
```
