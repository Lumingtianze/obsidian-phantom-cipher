# PhantomCipher

[English](./README.md) | [简体中文](./README_zh.md) | [日本語](./README_jp.md)

---

PhantomCipher provides a seamless transparent encryption experience for your Obsidian vault.

> [!CAUTION]
> **Warnings & Disclaimers**
> - **Early Stage**: This project is in its early stages. The encryption architecture may change at any time. Please check update logs frequently.
> - **Not for High-Security Use**: This plugin is not designed for high-stakes confidential or core business data. Be aware that Obsidian's Secret Storage API may not be fully hardened on all platforms.
> - **Backup Required**: Always **backup your entire vault** before encrypting important files. The author is not responsible for any data loss.
> - **Credential Backup**: Manually save/backup your KEK (Key Encryption Key) and DEK (Data Encryption Key). For multi-device use, you must manually sync these credentials across devices to avoid file isolation.
> - **Forgotten passwords result in permanent data loss.**

### ✨ Key Features

- **Envelope Encryption (V2)**: Uses KEK to wrap a DEK, allowing password changes without re-encrypting physical files.
- **Transparent Workflow**: Intercepts low-level I/O; write normally in the editor while files are stored encrypted on disk.
- **Built-in Compression**: Uses Deflate to offset the size increase from Base64 encoding.
- **Large Attachment Support**: Optimized for files up to 2GB. Note: Due to JS environment limits and the "Write-Verify-Replace" safety mechanism, high-memory devices (16GB+) are recommended for very large files.
- **Native Binary Format**: supports storing encrypted payloads in pure binary, improving performance for media files and eliminating Base64 overhead.
- **Integrity Verification**: Manual conversion now uses **MurmurHash3 plaintext hashing** to verify data integrity before and after encryption, preventing data corruption.

### 🚀 Quick Start

1. Go to settings and select **Manage Master Password**.
2. Set your password in the modal. The system will derive a KEK and generate a random DEK stored in Obsidian's Secret Storage.
3. **Important (Credential Export)**: Since the keys are stored in the keychain, **please be sure to manually record and export** the key values starting with `phantom-kek-` and `phantom-dek-` displayed on the keychain key list interface. It is recommended to store these values in an offline password manager.
4. Set **Operation mode** to "Auto-encrypt".
5. Use the **Ribbon Icon** or **Context Menu** to toggle encryption for files or folders.

## 🛠️ Decryption Tool
To decrypt files outside of Obsidian (e.g., for data export), use our CLI tool:
[PhantomCipher CLI Tool](https://github.com/Lumingtianze/phantom_decrypt)

## License
This project is licensed under the [Mozilla Public License 2.0 (MPL-2.0)](./LICENSE).
