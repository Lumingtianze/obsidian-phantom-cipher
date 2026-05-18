# Contributing to PhantomCipher

Thank you for your interest in this project! 

### Contribution Policy
Please be advised that this project is **currently not accepting any external contributions**, including Pull Requests, code refactors, or new feature implementations from third parties.

### Why?
As a security-focused plugin involving sensitive encryption logic and low-level vault interceptions, the maintainer keeps absolute control over the codebase to ensure:
1. **Security Integrity**: To prevent any potential introduction of vulnerabilities or "backdoors."
2. **Accountability**: Every single line of cryptographic code must be vetted and implemented by the sole author.
3. **Prevention of Catastrophic Data Loss**: Unlike standard plugins, PhantomCipher operates on the low-level DataAdapter and Vault layers. A minor logic error in these interceptions could lead to irreversible data corruption. To manage this high-stakes risk, the primary maintainer retains exclusive control over all I/O-related logic.

### Bug Reports
If you encounter a bug or a security vulnerability, please feel free to open an **Issue**. However, please do not submit a Pull Request with a fix; once verified, the fix will be implemented by the project maintainer.

---
*Essentially: I code alone. Thank you for respecting the solo-maintenance nature of this project.*
