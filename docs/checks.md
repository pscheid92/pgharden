# Security Checks Reference

90 checks across 8 sections. Each check declares its source (e.g., CIS PostgreSQL 16 Benchmark). Checks that cannot run in the current environment are automatically skipped.

## Legend

**Type:**

| Value    | Meaning                              |
|----------|--------------------------------------|
| `Auto`   | Fully automated check                |
| `Manual` | Requires human review of the finding |

**Requires:**

| Value | Meaning                        |
|-------|--------------------------------|
| `SQL` | Database query                 |
| `FS`  | Filesystem access              |
| `Cmd` | System command execution       |
| `SU`  | Superuser privilege            |
| `HBA` | Access to pg_hba.conf          |
| `—`   | No automated requirements      |

**Platform columns (BM = bare-metal, CT = container, RDS = managed cloud):**

| Value | Meaning                                                         |
|-------|-----------------------------------------------------------------|
| `Y`   | Check runs normally                                             |
| `~`   | Check runs with platform-specific adjustments (see notes below) |
| `X`   | Check is automatically skipped                                  |
| `M`   | Manual check — reported for human review regardless of platform |

**†** = check requires the `--local` flag (filesystem or command access to the host).

---

## Section 1 — Installation and Patches

| ID    | Check                                                        | Type   | Requires | BM | CT | RDS |
|-------|--------------------------------------------------------------|--------|----------|----|----|-----|
| 1.1   | Ensure packages are obtained from authorized repositories    | Manual | —        | M  | X  | X   |
| 1.1.1 | Ensure packages are obtained from PGDG repositories          | Auto   | Cmd †    | M  | X  | X   |
| 1.2   | Ensure systemd Service Files Are Enabled                     | Auto   | Cmd †    | Y  | X  | X   |
| 1.3   | Ensure Data Cluster Initialized Successfully                 | Auto   | FS †     | Y  | X  | X   |
| 1.4.1 | Ensure the configured PG version is consistent               | Auto   | FS †     | Y  | X  | X   |
| 1.4.2 | Ensure the PGDATA version is consistent                      | Auto   | FS †     | Y  | X  | X   |
| 1.4.3 | Ensure data checksums are enabled                            | Auto   | SQL      | Y  | Y  | Y   |
| 1.4.4 | Ensure WAL and temp are on separate storage                  | Auto   | FS †     | Y  | X  | X   |
| 1.4.5 | Ensure the audit of the storage type                         | Manual | —        | M  | M  | X   |
| 1.5   | Ensure PostgreSQL is at the latest version                   | Manual | —        | M  | M  | M   |
| 1.6   | Ensure PGPASSWORD is not set in shell profiles               | Auto   | FS †     | Y  | X  | X   |
| 1.7   | Ensure PGPASSWORD is not set in process environment          | Auto   | FS †     | Y  | X  | X   |
| 1.8   | Ensure extensions installed are authorized                   | Manual | SQL      | M  | M  | M   |
| 1.9   | Ensure tablespace locations are secure                       | Manual | SQL      | M  | M  | X   |

## Section 2 — Directory and File Permissions

| ID  | Check                                                        | Type   | Requires | BM | CT | RDS |
|-----|--------------------------------------------------------------|--------|----------|----|----|-----|
| 2.1 | Ensure the file permissions mask is correct                  | Auto   | Cmd †    | Y  | X  | X   |
| 2.2 | Ensure pg_wheel group membership is correct                  | Auto   | FS †     | Y  | X  | X   |
| 2.3 | Ensure psql command history is not maintained                | Auto   | FS †     | Y  | X  | X   |
| 2.4 | Ensure .pg_service.conf does not contain passwords           | Auto   | FS †     | Y  | X  | X   |
| 2.5 | Ensure pg_hba.conf permissions are restrictive               | Auto   | FS †     | Y  | X  | X   |
| 2.6 | Ensure Unix socket directory has restrictive permissions     | Auto   | FS †     | Y  | X  | X   |
| 2.7 | Ensure PGDATA directory has restrictive permissions          | Auto   | FS †     | Y  | X  | X   |
| 2.8 | Ensure PGDATA content is owned by the postgres user          | Manual | FS †     | Y  | X  | X   |

## Section 3 — Logging and Auditing

| ID     | Check                                                    | Type | Requires | BM | CT | RDS |
|--------|----------------------------------------------------------|------|----------|----|----|-----|
| 3.1.2  | Ensure log destinations are set correctly                | Auto | SQL      | Y  | Y  | ~   |
| 3.1.3  | Ensure the logging collector is enabled                  | Auto | SQL      | Y  | ~  | ~   |
| 3.1.4  | Ensure log file destination directory is set             | Auto | SQL      | Y  | ~  | X   |
| 3.1.5  | Ensure log filename pattern is set                       | Auto | SQL      | Y  | ~  | X   |
| 3.1.6  | Ensure log file permissions are correct                  | Auto | SQL      | Y  | ~  | X   |
| 3.1.7  | Ensure log_truncate_on_rotation is enabled               | Auto | SQL      | Y  | X  | X   |
| 3.1.8  | Ensure max log file lifetime is set (1d)                 | Auto | SQL      | Y  | X  | X   |
| 3.1.9  | Ensure max log file size is set (1GB)                    | Auto | SQL      | Y  | X  | X   |
| 3.1.10 | Ensure the correct syslog facility is set                | Auto | SQL      | Y  | Y  | Y   |
| 3.1.11 | Ensure syslog_sequence_numbers is enabled                | Auto | SQL      | Y  | Y  | Y   |
| 3.1.12 | Ensure syslog_split_messages is enabled                  | Auto | SQL      | Y  | Y  | Y   |
| 3.1.13 | Ensure the correct syslog_ident is set                   | Auto | SQL      | Y  | Y  | Y   |
| 3.1.14 | Ensure log_min_messages is set correctly                  | Auto | SQL      | Y  | Y  | Y   |
| 3.1.15 | Ensure log_min_error_statement is set correctly           | Auto | SQL      | Y  | Y  | Y   |
| 3.1.16 | Ensure debug_print_parse is disabled                     | Auto | SQL      | Y  | Y  | Y   |
| 3.1.17 | Ensure debug_print_rewritten is disabled                 | Auto | SQL      | Y  | Y  | Y   |
| 3.1.18 | Ensure debug_print_plan is disabled                      | Auto | SQL      | Y  | Y  | Y   |
| 3.1.19 | Ensure debug_pretty_print is enabled                     | Auto | SQL      | Y  | Y  | Y   |
| 3.1.20 | Ensure log_connections is enabled                        | Auto | SQL      | Y  | Y  | Y   |
| 3.1.21 | Ensure log_disconnections is enabled                     | Auto | SQL      | Y  | Y  | Y   |
| 3.1.22 | Ensure log line prefix is set correctly                  | Auto | SQL      | Y  | Y  | ~   |
| 3.1.23 | Ensure log_statement is set correctly                    | Auto | SQL      | Y  | Y  | Y   |
| 3.1.24 | Ensure log_timezone is set correctly                     | Auto | SQL      | Y  | Y  | Y   |
| 3.1.25 | Ensure log_error_verbosity is set correctly              | Auto | SQL      | Y  | Y  | Y   |
| 3.1.26 | Ensure log_hostname is disabled                          | Auto | SQL      | Y  | Y  | Y   |
| 3.1.27 | Ensure log_duration is disabled                          | Auto | SQL      | Y  | Y  | Y   |
| 3.2    | Ensure the pgAudit extension is enabled                  | Auto | SQL      | Y  | Y  | ~   |

## Section 4 — User Access and Authorization

| ID   | Check                                                    | Type   | Requires | BM | CT | RDS |
|------|----------------------------------------------------------|--------|----------|----|----|-----|
| 4.1  | Ensure postgres admin access is restricted               | Auto   | FS †     | Y  | X  | X   |
| 4.2  | Ensure login roles have password expiration              | Auto   | SQL, SU  | Y  | Y  | Y   |
| 4.3  | Ensure excessive admin privileges are revoked            | Auto   | SQL      | Y  | Y  | ~   |
| 4.4  | Ensure login roles have strong passwords                 | Manual | SQL      | M  | M  | M   |
| 4.5  | Ensure SECURITY DEFINER functions are secured            | Auto   | SQL      | Y  | Y  | Y   |
| 4.6  | Ensure excessive DML privileges are revoked              | Manual | SQL      | M  | M  | M   |
| 4.7  | Ensure Row Level Security is configured correctly        | Manual | SQL      | M  | M  | M   |
| 4.8  | Ensure the set_user extension / role hierarchy           | Manual | SQL, SU  | Y  | Y  | Y   |
| 4.10 | Ensure the public schema has appropriate privileges      | Auto   | SQL      | Y  | Y  | Y   |

## Section 5 — Connection and Login

| ID   | Check                                                    | Type | Requires | BM | CT | RDS |
|------|----------------------------------------------------------|------|----------|----|----|-----|
| 5.1  | Ensure no passwords visible in process listings          | Auto | Cmd †    | Y  | X  | X   |
| 5.2  | Ensure listen_addresses is configured correctly          | Auto | SQL      | Y  | ~  | X   |
| 5.3  | Ensure HBA local connections use secure auth             | Auto | HBA      | Y  | Y  | X   |
| 5.4  | Ensure HBA host connections use secure auth              | Auto | HBA      | Y  | Y  | X   |
| 5.5  | Ensure connection limits are configured                  | Auto | SQL      | Y  | Y  | ~   |
| 5.6  | Ensure password complexity validation is configured      | Auto | SQL      | Y  | Y  | Y   |
| 5.7  | Ensure authentication timeout and delay are configured   | Auto | SQL      | Y  | Y  | ~   |
| 5.8  | Ensure SSL/GSSENC is used for all host connections       | Auto | HBA      | Y  | Y  | X   |
| 5.9  | Ensure network CIDR ranges are minimized                 | Auto | HBA      | Y  | Y  | X   |
| 5.10 | Ensure specific databases and users are specified        | Auto | HBA      | Y  | Y  | X   |
| 5.11 | Ensure superuser connections are restricted              | Auto | HBA      | Y  | Y  | X   |
| 5.12 | Ensure password encryption is set to scram-sha-256       | Auto | SQL      | Y  | Y  | Y   |
| 5.13 | Ensure HBA rule ordering doesn't shadow rules            | Auto | HBA      | Y  | Y  | X   |

## Section 6 — PostgreSQL Settings

| ID   | Check                                                    | Type   | Requires | BM | CT | RDS |
|------|----------------------------------------------------------|--------|----------|----|----|-----|
| 6.2  | Ensure 'backend' runtime parameters are safe             | Auto   | SQL      | Y  | Y  | Y   |
| 6.3  | Ensure 'postmaster' parameters are reviewed              | Manual | SQL      | M  | M  | M   |
| 6.4  | Ensure 'sighup' parameters are reviewed                  | Manual | SQL      | M  | M  | M   |
| 6.5  | Ensure 'superuser' parameters are reviewed               | Manual | SQL      | M  | M  | M   |
| 6.6  | Ensure 'user' parameters are reviewed                    | Manual | SQL      | M  | M  | M   |
| 6.7  | Ensure FIPS 140-2 OpenSSL cryptography is used           | Auto   | Cmd †    | Y  | X  | X   |
| 6.8  | Ensure TLS is enabled and configured correctly           | Auto   | SQL      | Y  | Y  | ~   |
| 6.9  | Ensure a cryptographic extension is installed            | Manual | SQL      | M  | M  | M   |
| 6.10 | Ensure SSL ciphers are configured correctly              | Auto   | SQL      | Y  | Y  | ~   |
| 6.11 | Ensure data anonymization extension is configured        | Auto   | SQL      | Y  | Y  | Y   |
| 6.12 | Ensure idle_in_transaction_session_timeout is set         | Auto   | SQL      | Y  | Y  | Y   |
| 6.13 | Ensure statement_timeout is set                          | Auto   | SQL      | Y  | Y  | Y   |
| 6.14 | Ensure lock_timeout is set                               | Auto   | SQL      | Y  | Y  | Y   |

## Section 7 — Replication

| ID  | Check                                                      | Type | Requires | BM | CT | RDS |
|-----|------------------------------------------------------------|------|----------|----|----|-----|
| 7.1 | Ensure a replication-only user is configured               | Auto | SQL      | Y  | Y  | ~   |
| 7.2 | Ensure replication commands are logged                     | Auto | SQL      | Y  | Y  | Y   |
| 7.4 | Ensure WAL archiving is configured                         | Auto | SQL      | Y  | Y  | X   |
| 7.5 | Ensure streaming replication parameters are correct        | Auto | SQL      | Y  | Y  | X   |

## Section 8 — Special Configuration

| ID  | Check                                                      | Type   | Requires | BM | CT | RDS |
|-----|------------------------------------------------------------|--------|----------|----|----|-----|
| 8.2 | Ensure a backup and recovery tool is configured            | Auto   | Cmd †    | Y  | Y  | X   |
| 8.3 | Ensure special file/program config is reviewed             | Manual | SQL      | M  | M  | M   |

---

## Omitted CIS Benchmark IDs

These CIS benchmark IDs are intentionally not implemented as standalone checks:

| ID    | Reason                                            |
|-------|---------------------------------------------------|
| 3.1.1 | Merged into 3.1.2 (same setting)                  |
| 4.9   | Merged into 4.8 (role hierarchy review)            |
| 6.1   | Internal-context parameters cannot be changed      |
| 7.3   | Requires external infrastructure inspection        |
| 8.1   | Covered by 1.4.4 and 2.7                           |

---

## Platform-Specific Behavior

Checks marked `~` run with adjustments for the detected environment:

| ID      | Adjustment                                                                   |
|---------|------------------------------------------------------------------------------|
| 3.1.2   | RDS/Aurora: log_destination is stderr (managed)                              |
| 3.1.3   | Container: logging_collector=off acceptable (stdout). RDS/Aurora: always off |
| 3.1.4-6 | Only relevant when logging_collector=on                                      |
| 3.1.22  | RDS/Aurora set their own log_line_prefix format                              |
| 3.2     | RDS/Aurora: check pg_extension instead of shared_preload_libraries           |
| 4.3     | RDS/Aurora: rdsadmin excluded from superuser count                           |
| 5.2     | Container: listen_addresses='*' expected                                     |
| 5.5     | RDS/Aurora: built-in roles excluded                                          |
| 5.7     | RDS/Aurora: auth_delay not available                                         |
| 6.8     | RDS/Aurora: SSL managed by AWS                                               |
| 6.10    | RDS/Aurora: cipher list managed by AWS                                       |
| 7.1     | RDS: rds_replication role serves as dedicated replication user                |

---

## Environment Compatibility

pgharden detects the runtime environment and skips checks that do not apply:

| Environment        | Description                          | Detection method            |
|--------------------|--------------------------------------|-----------------------------|
| Bare-metal (BM)    | Traditional server or VM install     | Default / `--platform bm`  |
| Container (CT)     | Docker, Kubernetes, Kubernetes operators    | `/.dockerenv` or cgroup     |
| Managed cloud (RDS)| AWS RDS, Aurora, or similar service  | `rds_` functions in SQL     |
