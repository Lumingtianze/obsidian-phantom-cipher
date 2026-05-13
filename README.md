# PhantomCipher

[English](./README.md) | [简体中文](./README_zh.md) | [日本語](./README_jp.md)

---

PhantomCipher provides a seamless transparent encryption experience for your Obsidian vault.

> [!CAUTION]
> - This plugin is for personal use only; please do not use it to process highly confidential or core business data.
> - Before encrypting important files, **please make sure to back up your repository**.
> - The author is not responsible for any form of data loss.
> - **Forgetting your password will result in permanent loss of your files.**

## ✨ Features
- **Argon2id + AES-GCM**: Industry-standard security to protect your data.
- **Transparent Logic**: Intercepts read/write operations; edit your notes as usual while they are stored encrypted on disk.
- **Compression**: Built-in Deflate compression to counteract Base64 bloat.
- **Performance**: Optimized with "Session Salt" to ensure smooth editing even with large vaults.
- **Secure Storage**: Master passwords are saved in your system's secure keychain.

## 🚀 Quick Start
1. Go to settings and configure the **Set master password** option. 
2. Click **Link...** to open the system keychain, then click **Add secret...**. Set an ID (name) and enter your actual password into the **Secret value** field, then save and select it.
3. Change **Operation mode** to "Auto-encrypt".
4. Use the **Ribbon icon** or **Right-click menu** to manually toggle encryption for specific files or folders.

## License

This project is licensed under the [Mozilla Public License 2.0 (MPL-2.0)](./LICENSE).
