# rcrm_gui

The Flutter GUI for RCrm, an encrypted media library browser. It uses Riverpod
for state, `media_kit` for video playback and `dart:ffi` to talk to the Rust
`rcrm-flutter-bridge`: the bridge runs the read-only WebDAV / FTP server and
decodes media on the fly, so no plaintext is written to disk. This project
requires Flutter 3.50+ / Dart 3.14+ and uses the official `material_ui` package
in place of `package:flutter/material.dart`.

## Build / run

Build from the repository root using the platform scripts — see
`../../docs/BUILDING.md` (for example
`powershell -File ../../scripts/build_windows.ps1 -Release` or
`../../scripts/build_android.ps1 -Release -SplitAbi`). The native bridge is
always compiled in release mode, even for a debug Flutter build.

## Test / analyze

Run from this directory:

```bash
flutter analyze lib test
flutter test
```

## Documentation

Architecture, C-ABI/ownership rules and UI guidelines live in `../../docs/`
(`ARCHITECTURE.md`, `API_REFERENCE.md`, `DESIGN.md`, `BUILDING.md`).
