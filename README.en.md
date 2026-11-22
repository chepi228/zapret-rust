# zapret rust 1.0

DPI circumvention for YouTube and Discord with automatic strategy selection and an optional local Telegram proxy. The Windows x64 build uses [zapret2](https://github.com/bol-van/zapret2) and [Flowseal strategies](https://github.com/Flowseal/zapret-discord-youtube). The menu is in Russian.

[Downloads and SHA-256 checksums](https://github.com/chepi228/zapret-rust/releases/latest) · [Русский](README.md)

## Windows

1. Extract the ZIP, RAR or 7z archive. Run `zapret-rust.bat` and approve the Windows elevation prompt.
2. Select **6** to check the connection and **1** to start. Use **3** for automatic strategy selection or **5** for manual selection.
3. Use **4** to manage the local Telegram proxy, **7 → 6** for Windows startup and **7 → 9** for built-in updates.

The native Rust application handles the menu, diagnostics, strategy selection, Windows services and Telegram. Standard profiles are built into the packet engine, and Luna Core runs custom Lua scripts. Rust ownership and bounds checks help prevent resource and memory errors.

The standard Windows x64 package uses the project's Rust engine, controller, worker, Telegram integration and ring library. It depends on the third-party WinDivert driver and Windows system libraries. [Engine build and package variants](native/zapret-ring-ffi/README.md#native-windows-engine).

The repository also contains C references, test scripts and legacy compatibility files. The rules in `.gitattributes` exclude those files from the GitHub language chart.

## Linux

The Linux installer verifies and runs the interactive setup from upstream [zapret2 v1.0.7](https://github.com/bol-van/zapret2/releases/tag/v1.0.7). The Rust engine and Windows menu are Windows features in this release.

```sh
sh zapret-rust-v1.0-linux-install.sh
```

Use `--prepare-only` to unpack and prepare the program before running the system setup. See the [Linux instructions](https://github.com/chepi228/zapret-rust/blob/v1.0/docs/linux.md).

## Contact and support

Telegram [@chepi1](https://t.me/chepi1).

USDT on TRC-20  
`TM9NUBAggxULA56T4wYrTyxfQX4bPMjDM9`

Project source is [MIT](LICENSE). [Third-party notices](THIRD-PARTY-NOTICES.md) document bundled components and their source code.
