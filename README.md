# 😇 Guardian Angel

**A free, open-source self-control app that locks in your DNS filter for the moments you need it most.**

Guardian Angel doesn't filter the internet. **You** choose the filter (a public one like CleanBrowsing or Cloudflare for Families, NextDNS, or your own AdGuard Home or Pi-hole server), and Guardian Angel makes sure you can't switch it off on impulse. To change it, loosen it, or uninstall the app, you either wait out a delay you set or get a code from someone you trust.

> ⚠️ **Status: early development.** Guardian Angel isn't ready for everyday use yet. Please don't install development builds on a computer you rely on. Test in a virtual machine.

---

## Why

In a strong moment, it's easy to set up a filter. In a weak moment, it's just as easy to turn it off. Guardian Angel puts time and accountability between you and that choice, so your decision from the strong moment is the one that holds.

It's made as an act of service, for the sake of God. It's free for everyone, with no ads, no accounts, and no data collection.

---

## How it works

1. **Pick your filter.** Use any DNS filter you like. Guardian Angel tests it before locking, so you can't lock in a filter that doesn't work.
2. **Choose how you unlock.**
   - ⏳ **Time delay:** any change that loosens protection has to wait out the delay you chose. You can set longer delays for late nights.
   - 🤝 **Accountability partner:** a trusted person scans a QR code with any authenticator app. Their 6-digit code can approve a change right away. No servers or email needed.
3. **Click Lock.**

From then on:
- **Tightening protection is instant.** A stricter filter or a longer delay takes effect right away.
- **Loosening protection is delayed.** You request the exact change, and it applies automatically once the delay is over. You can cancel it anytime.
- **Uninstalling counts as loosening too,** so it also has to wait out the delay.

---

## Features

**Core lock**
- Locks DNS on every network adapter (IPv4 and IPv6, including encrypted DNS)
- A firewall lock that allows DNS only to your chosen filter
- Stops browsers from using their own DNS-over-HTTPS to get around your filter
- Guards the hosts file and detects VPNs and proxies
- Fails closed: if something breaks, you stay filtered, not unfiltered
- The timer can't be skipped by changing the system clock

**Stronger protection**
- 🔐 **Vault:** a time-locked store for passwords you want protected from yourself (router, filter dashboard, BIOS, phone Screen Time code)
- 👤 **Managed admin:** keeps your daily account standard, with a hidden admin account whose password rotates after every use
- 🛡️ **Security scan:** finds the ways around your filter, fixes them, and locks them
- 🚫 **Application control:** blocks portable apps from running out of Downloads or USB drives
- 📦 **Protected apps:** stops chosen apps (like Tailscale) from being opened or uninstalled
- 💾 **Boot and reset hardening:** a guided checklist (BIOS password, BitLocker, recovery settings) so even a reset stays behind your delay

**Beyond your computer**
- Guides for locking your router, iPhone (supervised mode and a configuration profile generator), and Android

---

## Setup options

| Setup | Best for |
|---|---|
| **Simple** | One public filter for everything. Easiest. |
| **Home + on the go** | Your own home DNS server, with a public filter when you're away |
| **Own server everywhere** | Your own filter reached anywhere through Tailscale |

The app walks you through whichever one you choose.

---

## Platforms

| Platform | Status |
|---|---|
| Windows 11 | 🚧 In development |
| iPhone / iPad | 📋 Planned (profile generator and guide) |
| macOS | 📋 Planned |
| Android | 📋 Planned (guide, then app) |

---

## Honest limits

No software can stop someone who is fully determined and has physical access to the computer. Guardian Angel's goal is to make getting around it take far longer than a weak moment lasts. With every protection turned on, removing it should take a full factory reset, and the reset itself sits behind your lock unless someone physically opens the computer.

Guardian Angel works best alongside real accountability: a partner, a community, and your own reasons for doing this.

---

## Safety

- **There are no backdoors.** Release builds have no master key or hidden bypass. The code is public, so you can check this yourself.
- **Keep your recovery sheet.** During setup you'll get a printable recovery sheet. Give it to your accountability partner in a sealed envelope.
- **Test first.** Try it in a virtual machine before using it on your main computer.

---

## Contributing

Bug reports, bypass reports, and pull requests are welcome. If you find a way around Guardian Angel, please open an issue so it can be fixed for everyone.

## Support the project

Guardian Angel is free and always will be. If it helps you and you'd like to support it, a donation link will be added here soon. Sharing it with someone who needs it helps just as much.

## License

[GPL-3.0-or-later](LICENSE), so Guardian Angel and every version of it stays free and open for everyone.

## For developers

See [CLAUDE.md](CLAUDE.md) for the architecture and design rules, [docs/PROTECTIONS.md](docs/PROTECTIONS.md) for every protection and how it's tested, and [docs/VM-TESTING.md](docs/VM-TESTING.md) for building and testing in a virtual machine.
