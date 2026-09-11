# icc - Instacrypt CLI


### 👁️‍🗨️ Summary
---

A terminal-based post-quantum ready, file encryption assistant by [Instacrypt](https://instacrypt.io) powered by the [icfx](https://github.com/instacryptio/icfx/) cryptographic library.


### 🪶 Features
---

- Post-quantum hybrid encryption (X25519 + ML-KEM-768)
- Digital signatures (ML-DSA-65 / FIPS 204)
- ICFX output formats
- Identity management (multiple identities)
- Contact management with lock (public key) storage
- Group management (user defined groups of contacts)
- OS keychain integration with file-based fallback
- Key import/export with passphrase protection
- Lock (public key) sharing - file and animated QR
- Profile backup/restore
- Optional cloud sync (contacts, groups, settings, and identity-key roaming) with TOTP and hardware-key (WebAuthn) 2FA
- Shell completions (bash, zsh, fish, powershell)
- Signature verification with contact/identity lookup
- Securely sharing files with contacts via Instacrypt Cloud w/ a [paid plan](https://instacrypt.io/pricing).
- Signing git commits


### 🖥 OS Support
---

- Linux
- macOS
- FreeBSD (14.4+)
- OpenBSD (7.8 & 7.9)
- Windows


### 🔌 Installation
---

**Linux / macOS / FreeBSD / OpenBSD** — one-line install:

```sh
curl -sL https://instacrypt.io/ic-cli/install.sh | bash
```

**Windows** — download and run [install.bat](https://instacrypt.io/ic-cli/install.bat).

Prebuilt binaries for every release are attached to the [GitHub Releases](https://github.com/instacryptio/ic-cli/releases) page. To uninstall, run `curl -sL https://instacrypt.io/ic-cli/uninstall.sh | bash` (or `uninstall.bat` on Windows).

See the [Installation Guide](https://instacrypt.io/docs/installation) for details.
 

### 📖 Usage
---

See [Documentation](https://instacrypt.io/docs/usage)


### ⚗️ Tech Stack
---

This application was built with [Go](https://go.dev/), [Cobra](https://github.com/spf13/cobra), [Lipgloss](https://github.com/charmbracelet/lipgloss), and the [icfx](https://github.com/instacryptio/icfx/) cryptographic library.


### 📜 License
---

[Apache 2.0](LICENSE)


### 🗺️ Future Features
---

- Auto-detect Instacrypt encrypted USB key that stores your identities.


### 💰 Support
---

This application will remain free and open source forever. The overall project hopes to remain sustainable via the Instacrypt Cloud paid plans.

Otherwise, you can support this project simply by giving our repo a star or buying us a coffee:

[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/yellow_img.png)](https://www.buymeacoffee.com/3dfosi)

Be sure to mention "Instacrypt" in the "Say something nice..." field so we know what project the coffee is for. 🙏
