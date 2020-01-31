Adds DevAudit scan to OWASP Dependency Check. It is an ODC plugin.

The plugin relies on index provided by nuget-indexer . The index is stored in ODC vulnerability database, so there is no need for extra configuration.

Config properties:

* com.ysoft.dotnetEnhancer.enabled – enables/disables the analyzers
* com.ysoft.dotnetEnhancer.vulnerabilityMode – CVE_ONLY uses description from NVD and ignores vulnerabilities without CVE; CVE_PREFERRED prefers description from NVD, but allows some best-effort output if CVE is not available; PURE_DA always uses data from DevAudit.
* com.ysoft.dotnetEnhancer.devAuditPath – Path to DevAudit folder. On Linux, it is expected that devaudit.exe is executable and binfmt is configured for running .NET binaries.
* com.ysoft.dotnetEnhancer.strictSearch – Raises exception instead of warning if a .NET library could not be found in index.
