# zapret-rust 1.3

**YouTube, Discord and Telegram Desktop on Windows 10/11 x64.** If your ISP restricts access through deep packet inspection (DPI), zapret-rust helps you choose a strategy for your connection. One menu lets you start the bypass, test Discord attachments and connect Telegram to a local bridge.

**[Download the Windows x64 ZIP](https://github.com/chepi228/zapret-rust/releases/download/v1.3/zapret-rust-v1.3-windows-x64.zip)** · [All release files](https://github.com/chepi228/zapret-rust/releases/tag/v1.3) · [What's new in 1.3](CHANGELOG.md) · [Русский](README.md)

## Start on Windows

1. Extract the entire ZIP into a permanent folder, for example `C:\Tools\zapret-rust`.
2. Open `zapret-rust.exe` and approve the Windows administrator prompt. The first launch refreshes six shared lists and checks PC compatibility. Find the report in `runtime\pc-check-last.json`.
3. Choose **1** to start. Open the service you want to use and try an everyday action such as playing a video, loading an image or joining a voice call.
4. If the service still loads slowly, choose **3 → 1**. The quick test tries profiles on the current connection. Run it between games and calls because it temporarily stops the active bypass to take measurements.

If GitHub Raw is unreachable, the program also tries the GitHub API and your Windows proxy settings. During an outage it uses the bundled lists or the last successful update. Open **7 → 8** to see when the lists were updated or retry immediately. With usable local lists, the next automatic attempt is on a menu launch at least ten minutes after the failed first update.

To move from a release with a BAT launcher, extract this ZIP into a separate folder. To carry over settings and custom lists, close both menus and copy `runtime\settings.ini` and your `lists\*-user.txt` files.

## How it compares with Flowseal

Both projects help users reach services affected by DPI and test strategies on their connection. Flowseal distributes ready-to-run BAT configurations. zapret-rust brings together strategies from Flowseal and work from zapret2 in a Windows package with its own Rust engine, controller and Telegram bridge.

| Task | Flowseal/zapret-discord-youtube | zapret-rust |
| --- | --- | --- |
| Start a strategy | Open a `general*.bat` file. Use `service.bat` to install the chosen configuration as a service. | Open `zapret-rust.exe`. Choose **1** to start, **5** to pick another profile, or **7 → 6** to start with Windows. |
| Find a working profile | In `service.bat`, choose **Run Tests → Standard tests → All configs**. **DPI checkers** are also available. | **3 → 1** compares up to 18 profiles against a baseline with the bypass off, then retests the finalists. **3 → 2** tests all 36 profiles. |
| Connect Telegram Desktop | The README links to the separate **tg-ws-proxy** project. | **4 → 1** starts the built-in bridge and opens its connection link in Telegram. Downloads use a dedicated pool of connections. |
| Diagnose Discord | `service.bat` offers diagnostics, Discord cache cleanup and a hosts update for voice chat. | **6** downloads a sample attachment and checks its SHA-256. **8 → 12** checks voice connectivity separately. |

[Flowseal's repository and usage guide](https://github.com/Flowseal/zapret-discord-youtube) · [Flowseal's TG WS Proxy](https://github.com/Flowseal/tg-ws-proxy) · [Upstream zapret2](https://github.com/bol-van/zapret2)

## Files in the Windows archive

| File or folder | Purpose |
| --- | --- |
| `zapret-rust.exe` | Opens the main menu for setup, profile selection and updates. |
| `bin/` | Controller, worker processes and the WinDivert driver for Windows x64. |
| `strategies/` and `lists/` | Bundled profiles and the domain and IP lists they use. |
| `tools/targets.txt` | Addresses used to test strategies. |

## Read the results

The first row is the baseline with the bypass off. Quick selection tests up to **18 strategies**. It measures the current profile against all **88 targets** and screens challengers on a common subset, including a Discord media file, a Roblox game icon and services that failed on this connection. The three leading challengers advance to the full panel, along with additional profiles that cover the remaining observed service recoveries. A verified standby can replace an unstable control. If the short screen cannot confirm two controls, all remaining candidates advance to the full panel. Choose **3 → 2** to run all strategies.

| During a trial | Meaning |
| --- | --- |
| Green, e.g. `32/68 (+4)` | Four more targets responded than in the baseline. |
| Neutral, e.g. `28/68 (=)` | The same number responded. |
| Red, e.g. `26/68 (-2)` | Two fewer targets responded. |
| Yellow | The controls were unstable or the measured target set changed. |
| Score and score leader | Retries and regressions on control sites affect the score used to select finalists. |

In the standard test, the results table shows trial speed scores relative to the reference profile (0). Each comparable address scores `100 × (reference time − candidate time) / max(reference time, candidate time)`. The selector averages addresses within each group, then gives each group equal weight. A speed-based switch requires preserving working services and scoring at least +3 points in both working comparisons. The selector also takes the lower score for each service group across the two orders. The average of those lower scores must reach +3.

The final check runs the candidate in its working configuration. In the final table, green means it passed and red means it failed. If the proposed configuration is rejected, the summary gives the reason and names the profile that was kept. Choose **3 → 5** to reopen the latest result. The summary lists the detailed report file.

When a service retry separates two candidates, the selector rechecks that service. A persistent advantage is tested in reverse order. If the difference disappears and no other advantage is confirmed, the current profile stays selected.

Choose **4 → 4** to check the local Telegram bridge and see response times for media DC2 and DC4. To test file downloads, start the menu with your Telegram application's `ZAPRET_TEST_TG_API_ID` and `ZAPRET_TEST_TG_API_HASH` and a dedicated test bot's `ZAPRET_TEST_TG_BOT_TOKEN` in the environment. The probe downloads a small public sticker through the same bridge and reports all three results separately.

Press **Ctrl+C** to cancel. The controller temporarily disables mouse text selection in the classic Windows console during a run so an accidental click cannot pause output halfway through.

## Menu shortcuts

| Task | Menu |
| --- | --- |
| Start or restart | **1** |
| Stop running zapret instances, including instances from other folders | **2** |
| Try all strategies or add a browser check | **3 → 2** or **3 → 3** |
| Pick a strategy manually | **5** |
| Diagnose the connection, VPN, proxy and conflicts | **6** |
| Configure Windows startup | **7 → 6** |
| Check for updates | **7 → 9** |
| Check DNS, TCP, TLS and HTTP separately | **8 → 11** |
| Remove the Windows registration | **7 → 11** |

### Telegram Desktop

Choose **4 → 1**, then accept the proxy link in Telegram Desktop. The bridge listens on `127.0.0.1`. Choose **4 → 3** to change its port or **4 → 2** to stop it.

### Troubleshooting

- If images load on one ISP and disappear on another, choose **6**. It compares IPv4 and IPv6 answers from Windows and DNS over HTTPS, including the Roblox thumbnail host. If Windows returns no address, the check reports the hostname when TLS validation succeeds at an alternative address.
- If Discord opens but images stall, choose **6** to download and verify a complete Discord media file. If the DNS address fails and the alternative works, the menu offers to pin the media hostname to the verified address. See **3 → 5** for strategy test results or **8 → 12** for Discord voice diagnostics.
- If the browser behaves differently from the quick test, **8 → 10** checks the browser's actual HTTP/2 and HTTP/3 connections. Use **6** to see whether a VPN or proxy is active.
- If the original connection briefly drops and returns, Auto Pick starts its measurements over once. If you switch networks, run **3 → 1** on the new connection. **3 → 5** shows the last network interruption and **8 → 4** includes it in the diagnostic report.
- Auto Pick needs successful responses from two distinct control hosts before selecting a profile. It repeats the baseline when too few controls respond, then reports the number of DNS failures if the check fails again. If an alternative profile's engine exits during screening, the report records the profile and its exit code.
- If a CDN address accepts TCP but rejects TLS, the probe and built-in downloader try the remaining DNS addresses. Each connection verifies the original hostname. Auto Pick pins a peer after a successful baseline and uses requests with multiple TLS connections to measure availability.
- After more than 16 failed requests, Auto Pick retries a sample across services with fewer concurrent requests. If two distinct services recover, it rechecks the remaining addresses that timed out or failed to connect over TCP. The report includes the number of expanded retries.

The Windows guide covers all menu options, custom lists and recovery after an interrupted update. [Windows guide in Russian](https://github.com/chepi228/zapret-rust/blob/v1.3/docs/windows.md)

## Downloads and Linux

The ZIP, 7z and RAR for manual installation contain the same `zapret-rust` folder. Windows can open the ZIP directly. [ZIP](https://github.com/chepi228/zapret-rust/releases/download/v1.3/zapret-rust-v1.3-windows-x64.zip) · [7z](https://github.com/chepi228/zapret-rust/releases/download/v1.3/zapret-rust-v1.3-windows-x64.7z) · [RAR](https://github.com/chepi228/zapret-rust/releases/download/v1.3/zapret-rust-v1.3-windows-x64.rar) · [SHA-256 checksums](https://github.com/chepi228/zapret-rust/releases/download/v1.3/SHA256SUMS.txt)

The separate Linux installer downloads upstream **zapret2 v1.0.7**, verifies its SHA-256 and opens its interactive setup. Add `--prepare-only` to prepare the files without installing the system service. [Linux installer](https://github.com/chepi228/zapret-rust/releases/download/v1.3/zapret-rust-v1.3-linux-install.sh) · [Linux guide in Russian](https://github.com/chepi228/zapret-rust/blob/v1.3/docs/linux.md)

```sh
sh zapret-rust-v1.3-linux-install.sh
```

## Components and credits

The standard Windows x64 package runs the project's Rust controller, worker, packet engine, ring library and Telegram bridge. Standard profiles are built in. Luna Core runs custom Lua scripts. Windows packet capture uses the third-party WinDivert driver and Windows system APIs. The source tree also contains test references and compatibility builds. [Engine and package variants](https://github.com/chepi228/zapret-rust/blob/v1.3/native/zapret-ring-ffi/README.md#native-windows-engine)

The project builds on zapret2 and work by Flowseal. Project code is licensed under MIT, and bundled third-party components retain their respective licenses. [zapret2](https://github.com/bol-van/zapret2) · [Flowseal strategies](https://github.com/Flowseal/zapret-discord-youtube) · [TG WS Proxy](https://github.com/Flowseal/tg-ws-proxy) · [MIT](licenses/LICENSE) · [Third-party notices](licenses/THIRD-PARTY-NOTICES.md)

The GitHub language chart follows the repository's `.gitattributes`. [Language chart rules](https://github.com/chepi228/zapret-rust/blob/v1.3/.gitattributes)

## Contact and support

Contact the maintainer on Telegram. [@chepi1](https://t.me/chepi1)

To support development, send USDT on the TRC-20 network to `TM9NUBAggxULA56T4wYrTyxfQX4bPMjDM9`.
