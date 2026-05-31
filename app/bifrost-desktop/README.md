# Bifrost Desktop

> The Bridge Is Watched.

A native desktop wrapper for the **Bifrost** security dashboard, built with
[Tauri v2](https://tauri.app). On launch it starts a local **Python guardian**
process; on exit it shuts the guardian down. The React frontend polls the
guardian's HTTP API at `http://127.0.0.1:8766` and falls back to mock data when
the guardian is unavailable.

---

## What's inside

```
bifrost-desktop/
├── index.html              # Vite entry
├── package.json            # frontend + Tauri CLI scripts
├── vite.config.ts          # base "./" so assets load over the tauri:// protocol
├── tsconfig.json
├── public/favicon.svg
├── src/                    # the full React + TypeScript frontend
└── src-tauri/              # the native Rust shell
    ├── Cargo.toml
    ├── build.rs
    ├── tauri.conf.json     # window, bundle (appimage), withGlobalTauri
    ├── capabilities/       # window + shell + notification permissions
    ├── icons/              # app icons
    └── src/
        ├── main.rs         # thin entry → bifrost_lib::run()
        └── lib.rs          # guardian process supervision + tray + commands
```

### Guardian lifecycle (Rust → Python)

`src-tauri/src/lib.rs` owns the guardian process:

- **start** automatically in `setup()` when the app launches.
- **stop** automatically on window close, tray "Quit", and app exit.
- Exposes four commands the frontend calls over `window.__TAURI__`:
  - `start_guardian` → `bool`
  - `stop_guardian` → `bool`
  - `guardian_status` → `bool` (true while the process is alive)
  - `get_guardian_port` → `number` (8766)

**Where the guardian script is found** (first match wins):

1. `BIFROST_GUARDIAN` environment variable — absolute path to your `.py` entry.
2. Bundled resource: `<resources>/guardian/guardian.py`.
3. Next to the executable: `<exe dir>/guardian/guardian.py`.

The interpreter defaults to `python3` (override with `BIFROST_PYTHON`). The
guardian is launched as `python3 <script> --port 8766`.

> Bring your own guardian: drop your Python program at one of the paths above,
> or point `BIFROST_GUARDIAN` at it before launching.

---

## Prerequisites (Linux)

Install the Tauri system dependencies (Arch Linux):

```bash
sudo ./scripts/setup-linux-build-env.sh
```

This installs all required native libraries and places `linuxdeploy` at:

`/usr/local/bin/linuxdeploy`

If needed, the install command used by the script is:

```bash
sudo pacman -S --noconfirm webkit2gtk-4.1 gtk3 base-devel libayatana-appindicator fuse2
wget -O /usr/local/bin/linuxdeploy https://github.com/linuxdeploy/linuxdeploy/releases/download/continuous/linuxdeploy-x86_64.AppImage
chmod +x /usr/local/bin/linuxdeploy
```

Then install the toolchains:

- **Rust** (stable): https://rustup.rs
  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  ```
- **Node.js 18+** and **pnpm**:
  ```bash
  npm install -g pnpm
  ```

---

## Develop

```bash
pnpm install
pnpm desktop:dev      # = tauri dev (starts Vite on :5173 + the native window)
```

`pnpm dev` alone runs just the web frontend in a browser (mock-data mode).

## Build a release bundle

```bash
pnpm install
pnpm desktop:build    # = tauri build
```

Artifacts are written to:

- `src-tauri/target/release/bundle/appimage/*.AppImage`

`src-tauri/tauri.conf.json` explicitly bundles only:

```json
"targets": ["appimage"]
```

## Arch Linux package (pacman / makepkg)

An Arch package recipe is provided at `PKGBUILD`.

```bash
cd app/bifrost-desktop
makepkg -si
```

This builds the desktop binary and installs:

- `/usr/bin/bifrost`
- `/usr/share/applications/bifrost.desktop`
- `/usr/share/icons/hicolor/256x256/apps/bifrost.png`

## Icons

The repo ships a generated icon set in `src-tauri/icons/`. To regenerate from a
single source image:

```bash
pnpm tauri icon path/to/source-1024.png
```

---

## Notes

- The window is **frameless** (`decorations: false`); the in-app title bar
  provides minimize / maximize / close via Tauri window commands.
- `withGlobalTauri` is enabled, so the frontend talks to the runtime through
  `window.__TAURI__` with no extra npm SDK dependency.
- In a plain browser (no Tauri runtime) every native call no-ops safely and the
  dashboard runs on mock data — handy for frontend-only iteration.
