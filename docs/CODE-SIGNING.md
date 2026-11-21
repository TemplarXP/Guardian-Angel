# Code signing

Windows shows a SmartScreen warning ("Windows protected your PC") for unsigned installers and for new certificates without reputation. Signing proves the installer came from you and hasn't been modified. Guardian Angel uses **two independent kinds of signatures**:

## 1. Authenticode (for Windows and SmartScreen)

| Option | Cost | Notes |
|---|---|---|
| **SignPath Foundation** | Free for qualifying open-source projects | **Recommended.** You apply with the public repo. Signing happens from GitHub Actions, and the key stays in SignPath's hardware security module, so it can't leak. The certificate is issued to SignPath Foundation, and they review the project and its build process. |
| **Certum Open Source Code Signing** | Low (roughly tens of euros a year, plus a card reader or their cloud key option) | Issued to you as an individual open-source developer. Needs identity verification. The cloud (SimplySign) version can be used from CI with some setup. |
| **Azure Trusted Signing** (Microsoft) | About US$10/month | Very easy from GitHub Actions. Eligibility for individuals is limited to certain countries and changes over time, so check the current requirements. |
| Commercial OV certificate (DigiCert, Sectigo, SSL.com...) | Hundreds per year | Since 2023, the private key must be on a hardware token or in a cloud HSM. EV certificates no longer skip SmartScreen reputation, so EV isn't worth the extra cost for this project. |

Whatever you choose, SmartScreen reputation builds up as people download the signed installer.

**Where it plugs in:** `.github/workflows/release.yml` has a placeholder step after "Build Release installer". The service, watchdog and app `.exe` files should be signed **before** the MSI is built, and then the MSI itself signed too. Keep certificate credentials in GitHub Actions secrets, never in the repo.

## 2. Guardian Angel's own signing key (for block lists and updates)
This is separate from Authenticode, and you own it completely.
- An **ECDSA P-256** key pair. The private key stays **offline** (an encrypted USB stick, or a password manager's secure file storage). The public key is compiled into the app (`src/GuardianAngel.Core/Lists/SignedList.cs`, `PublicKeyBase64`).
- Block lists (`data/lists/*.json`) are accepted only if they're signed with this key and have a higher version number than the list built into the app. That stops an old, weaker list from being replayed.
- The auto-updater (a later milestone) will install only update manifests signed with this key. Even a valid Authenticode signature from someone else won't be accepted.
- Until you generate the key, `PublicKeyBase64` is empty, so only the built-in lists are used and auto-update stays off. This is safe.
- If the key is ever lost, ship a new release with a new public key. If it's ever leaked, also publish a notice.

The `tools/GuardianAngel.Signer` command-line tool (key generation and signing) arrives with the updater milestone.
