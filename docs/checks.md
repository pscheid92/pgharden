# pgharden — Security Checks Reference

85 checks across 8 sections, based on the [CIS PostgreSQL Benchmark](https://www.cisecurity.org/benchmark/postgresql).

**Legend:**
- **Type**: `Auto` = fully automated, `Manual` = requires human review
- **Requires**: `SQL` = query only, `FS` = filesystem access, `Cmd` = system command, `SU` = superuser, `HBA` = pg_hba.conf access

---

## 1. Installation and Patches

| ID | Check | Type | Requires |
|----|-------|------|----------|
| 1.1 | Ensure packages are obtained from authorized repositories | Manual | — |
| 1.1.1 | Ensure packages are obtained from PGDG repositories | Auto | Cmd (`rpm`/`dpkg`) |
| 1.2 | Ensure systemd Service Files Are Enabled | Auto | Cmd (`systemctl`) |
| 1.3 | Ensure Data Cluster Initialized Successfully | Auto | FS |
| 1.4.1 | Ensure the configured PostgreSQL version is consistent with the running version | Auto | FS |
| 1.4.2 | Ensure the configured PostgreSQL cluster data directory version is consistent | Auto | FS |
| 1.4.3 | Ensure data checksums are enabled | Auto | SQL |
| 1.4.4 | Ensure WAL and temp are on separate storage if possible | Auto | FS |
| 1.4.5 | Ensure the audit of the storage type used to store the data | Manual | — |
| 1.5 | Ensure PostgreSQL is at the latest available version | Manual | — |
| 1.6 | Ensure PGPASSWORD is not set in shell profiles | Auto | FS |
| 1.7 | Ensure PGPASSWORD is not set in process environment | Auto | FS |
| 1.8 | Ensure PostgreSQL extensions installed are authorized | Manual | SQL |
| 1.9 | Ensure tablespace locations are secure | Manual | SQL |

## 2. Directory and File Permissions

| ID | Check | Type | Requires |
|----|-------|------|----------|
| 2.1 | Ensure the file permissions mask is correct (umask 0077) | Auto | Cmd (`sh`) |
| 2.2 | Ensure the PostgreSQL pg_wheel group membership is correct | Auto | FS |
| 2.3 | Ensure psql command history is not maintained | Auto | FS |
| 2.4 | Ensure .pg_service.conf does not contain passwords | Auto | FS |
| 2.5 | Ensure pg_hba.conf permissions are restrictive | Auto | FS |
| 2.6 | Ensure Unix socket directory has restrictive permissions | Auto | FS |
| 2.7 | Ensure PGDATA directory has restrictive permissions | Auto | FS |
| 2.8 | Ensure PGDATA content is owned by the postgres user | Manual | FS |

## 3. Logging and Auditing

| ID | Check | Type | Requires |
|----|-------|------|----------|
| 3.1.2 | Ensure the log destinations are set correctly | Auto | SQL |
| 3.1.3 | Ensure the logging collector is enabled | Auto | SQL |
| 3.1.4 | Ensure the log file destination directory is set correctly | Auto | SQL |
| 3.1.5 | Ensure the filename pattern for log files is set correctly | Auto | SQL |
| 3.1.6 | Ensure the log file permissions are set correctly (0600) | Auto | SQL |
| 3.1.7 | Ensure log_truncate_on_rotation is enabled | Auto | SQL |
| 3.1.8 | Ensure the maximum log file lifetime is set correctly (1d) | Auto | SQL |
| 3.1.9 | Ensure the maximum log file size is set correctly (1GB) | Auto | SQL |
| 3.1.10 | Ensure the correct syslog facility is set | Auto | SQL |
| 3.1.11 | Ensure syslog_sequence_numbers is enabled | Auto | SQL |
| 3.1.12 | Ensure syslog_split_messages is enabled | Auto | SQL |
| 3.1.13 | Ensure the correct syslog_ident is set | Auto | SQL |
| 3.1.14 | Ensure the log_min_messages is set correctly (warning) | Auto | SQL |
| 3.1.15 | Ensure the correct messages are written to the server log (error) | Auto | SQL |
| 3.1.16 | Ensure debug_print_parse is disabled | Auto | SQL |
| 3.1.17 | Ensure debug_print_rewritten is disabled | Auto | SQL |
| 3.1.18 | Ensure debug_print_plan is disabled | Auto | SQL |
| 3.1.19 | Ensure debug_pretty_print is enabled | Auto | SQL |
| 3.1.20 | Ensure log_connections is enabled | Auto | SQL |
| 3.1.21 | Ensure log_disconnections is enabled | Auto | SQL |
| 3.1.22 | Ensure the log line prefix is set correctly (%m %p %d %u %a %h) | Auto | SQL |
| 3.1.23 | Ensure log_statement is set correctly (ddl or all) | Auto | SQL |
| 3.1.24 | Ensure log_timezone is set correctly | Auto | SQL |
| 3.1.25 | Ensure log_error_verbosity is set correctly (verbose) | Auto | SQL |
| 3.1.26 | Ensure the log_hostname is disabled | Auto | SQL |
| 3.1.27 | Ensure the log_duration is disabled | Auto | SQL |
| 3.2 | Ensure the pgAudit extension is enabled | Auto | SQL |

## 4. User Access and Authorization

| ID | Check | Type | Requires |
|----|-------|------|----------|
| 4.1 | Ensure sudo or equivalent is used to limit postgres admin access | Auto | FS |
| 4.3 | Ensure excessive administrative privileges are revoked | Auto | SQL |
| 4.4 | Ensure login roles have strong passwords | Manual | SQL |
| 4.5 | Ensure SECURITY DEFINER functions are properly secured | Auto | SQL |
| 4.6 | Ensure excessive DML privileges are revoked | Manual | SQL |
| 4.7 | Ensure Row Level Security is configured correctly | Manual | SQL |
| 4.8 | Ensure the set_user extension is installed (role hierarchy review) | Manual | SQL, SU |
| 4.10 | Ensure the public schema has appropriate privileges | Auto | SQL |

## 5. Connection and Login

| ID | Check | Type | Requires |
|----|-------|------|----------|
| 5.1 | Ensure login via 'local' UNIX Domain Socket is configured correctly | Auto | Cmd (`ps`) |
| 5.2 | Ensure listen_addresses is configured correctly (not '*') | Auto | SQL |
| 5.3 | Ensure pg_hba.conf local connections use secure authentication | Auto | HBA |
| 5.4 | Ensure pg_hba.conf host connections use secure authentication | Auto | HBA |
| 5.5 | Ensure connection limits are configured | Auto | SQL |
| 5.6 | Ensure password complexity validation is configured | Auto | SQL |
| 5.7 | Ensure authentication timeout and delay are configured | Auto | SQL |
| 5.8 | Ensure SSL/GSSENC is used for all host connections | Auto | HBA |
| 5.9 | Ensure network CIDR ranges are minimized | Auto | HBA |
| 5.10 | Ensure specific databases and users are specified (not 'all') | Auto | HBA |
| 5.11 | Ensure superuser connections are restricted to local | Auto | HBA |
| 5.12 | Ensure password encryption is set to scram-sha-256 | Auto | SQL |

## 6. PostgreSQL Settings

| ID | Check | Type | Requires |
|----|-------|------|----------|
| 6.2 | Ensure 'backend' runtime parameters are configured correctly | Auto | SQL |
| 6.3 | Ensure 'postmaster' runtime parameters are configured correctly | Manual | SQL |
| 6.4 | Ensure 'sighup' runtime parameters are configured correctly | Manual | SQL |
| 6.5 | Ensure 'superuser' runtime parameters are configured correctly | Manual | SQL |
| 6.6 | Ensure 'user' runtime parameters are configured correctly | Manual | SQL |
| 6.7 | Ensure FIPS 140-2 OpenSSL cryptography is used | Auto | Cmd (`fips-mode-setup`) |
| 6.8 | Ensure TLS is enabled and configured correctly | Auto | SQL |
| 6.9 | Ensure a cryptographic extension is installed | Manual | SQL |
| 6.10 | Ensure SSL ciphers are configured correctly | Auto | SQL |
| 6.11 | Ensure data anonymization extension is configured | Auto | SQL |

## 7. Replication

| ID | Check | Type | Requires |
|----|-------|------|----------|
| 7.1 | Ensure a replication-only user is configured | Auto | SQL |
| 7.2 | Ensure replication commands are logged | Auto | SQL |
| 7.4 | Ensure WAL archiving is configured | Auto | SQL |
| 7.5 | Ensure streaming replication parameters are configured correctly | Auto | SQL |

## 8. Special Configuration Considerations

| ID | Check | Type | Requires |
|----|-------|------|----------|
| 8.2 | Ensure a backup and recovery tool is configured | Auto | Cmd (`pgbackrest`) |
| 8.3 | Ensure special file and program configuration is reviewed | Manual | SQL |

---

## Environment Compatibility

| Environment | SQL checks | HBA checks | FS checks | Cmd checks |
|-------------|-----------|------------|-----------|------------|
| Local (bare metal) | All | All | All | All available |
| Docker container | All | PG 15+ via SQL | Skipped | Limited |
| AWS RDS / Aurora | All | PG 15+ via SQL | Skipped | Skipped |
| Google Cloud SQL | All | PG 15+ via SQL | Skipped | Skipped |
| Azure Database | All | PG 15+ via SQL | Skipped | Skipped |
| Kubernetes pod | All | PG 15+ via SQL | Skipped | Limited |

Checks that cannot run in the current environment are automatically marked **SKIPPED** with a reason.
