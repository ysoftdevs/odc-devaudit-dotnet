# OWASP Dependency Check plugin for DevAudit

The plugin relies on index provided by [nuget-repository-indexer](https://github.com/ysoftdevs/nuget-repository-indexer) . The index is stored in database.

Config properties:

* com.ysoft.dotnetEnhancer.enabled – enables/disables the analyzers
* com.ysoft.dotnetEnhancer.vulnerabilityMode – CVE_ONLY uses description from NVD and ignores vulnerabilities without CVE; CVE_PREFERRED prefers description from NVD, but allows some best-effort output if CVE is not available; PURE_DA always uses data from DevAudit.
* com.ysoft.dotnetEnhancer.devAuditPath – Path to DevAudit folder. On Linux, it is expected that devaudit.exe is executable and binfmt is configured for running .NET binaries.
* com.ysoft.dotnetEnhancer.strictSearch – Raises exception instead of warning if a .NET library could not be found in index.
* com.ysoft.dotnetEnhancer.db.connectionString – JDBC URL for connection to the nuget-repository-indexer database
* com.ysoft.dotnetEnhancer.db.userName – username for DB specified in com.ysoft.dotnetEnhancer.db.connectionString
* com.ysoft.dotnetEnhancer.db.password – password for DB specified in com.ysoft.dotnetEnhancer.db.connectionString
