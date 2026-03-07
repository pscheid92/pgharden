# Platform x Check Matrix

Legend:
- **Y** = runs as-is, same expectations
- **~** = needs different expected value or behavior for this platform
- **X** = not applicable, should skip
- **M** = already manual review

## Section 1: Installation and Patches

| Check | What it does | bare-metal | container | zalando | rds | aurora |
|-------|-------------|:---:|:---:|:---:|:---:|:---:|
| 1.1 | Package repos (manual) | M | X | X | X | X |
| 1.1.1 | PGDG repos (rpm/dpkg) | M | X | X | X | X |
| 1.2 | systemd service enabled | Y | X | X | X | X |
| 1.3 | Data cluster initialized | Y | X | X | X | X |
| 1.4.1 | PG_VERSION matches running | Y | X | X | X | X |
| 1.4.2 | PGDATA version consistent | Y | X | X | X | X |
| 1.4.3 | Data checksums enabled | Y | Y | Y | Y | Y |
| 1.4.4 | WAL/temp separate storage | Y | X | X | X | X |
| 1.4.5 | Storage type audit (manual) | M | M | M | X | X |
| 1.5 | Latest PG version (manual) | M | M | M | M | M |
| 1.6 | PGPASSWORD in shell profiles | Y | X | X | X | X |
| 1.7 | PGPASSWORD in process env | Y | X | X | X | X |
| 1.8 | Extensions authorized (manual) | M | M | M | M | M |
| 1.9 | Tablespace locations (manual) | M | M | M | X | X |

## Section 2: Directory and File Permissions

| Check | What it does | bare-metal | container | zalando | rds | aurora |
|-------|-------------|:---:|:---:|:---:|:---:|:---:|
| 2.1 | umask is 0077 | Y | X | X | X | X |
| 2.2 | pg_wheel group / ext dir perms | Y | X | X | X | X |
| 2.3 | .psql_history disabled | Y | X | X | X | X |
| 2.4 | .pg_service.conf no passwords | Y | X | X | X | X |
| 2.5 | pg_hba.conf permissions | Y | X | X | X | X |
| 2.6 | Unix socket dir permissions | Y | X | X | X | X |
| 2.7 | PGDATA permissions 0700 | Y | X | X | X | X |
| 2.8 | PGDATA owned by postgres | Y | X | X | X | X |

## Section 3: Logging and Auditing

| Check | What it does | bare-metal | container | zalando | rds | aurora |
|-------|-------------|:---:|:---:|:---:|:---:|:---:|
| 3.1.2 | log_destination set | Y | Y | Y | ~ | ~ |
| 3.1.3 | logging_collector = on | Y | ~ | ~ | ~ | ~ |
| 3.1.4 | log_directory set | Y | ~ | ~ | X | X |
| 3.1.5 | log_filename set | Y | ~ | ~ | X | X |
| 3.1.6 | log_file_mode = 0600 | Y | ~ | ~ | X | X |
| 3.1.7 | log_truncate_on_rotation = on | Y | X | X | X | X |
| 3.1.8 | log_rotation_age = 1d | Y | X | X | X | X |
| 3.1.9 | log_rotation_size = 1GB | Y | X | X | X | X |
| 3.1.10 | syslog_facility set | Y | Y | Y | Y | Y |
| 3.1.11 | syslog_sequence_numbers = on | Y | Y | Y | Y | Y |
| 3.1.12 | syslog_split_messages = on | Y | Y | Y | Y | Y |
| 3.1.13 | syslog_ident set | Y | Y | Y | Y | Y |
| 3.1.14 | log_min_messages = warning | Y | Y | Y | Y | Y |
| 3.1.15 | log_min_error_statement = error | Y | Y | Y | Y | Y |
| 3.1.16 | debug_print_parse = off | Y | Y | Y | Y | Y |
| 3.1.17 | debug_print_rewritten = off | Y | Y | Y | Y | Y |
| 3.1.18 | debug_print_plan = off | Y | Y | Y | Y | Y |
| 3.1.19 | debug_pretty_print = on | Y | Y | Y | Y | Y |
| 3.1.20 | log_connections = on | Y | Y | Y | Y | Y |
| 3.1.21 | log_disconnections = on | Y | Y | Y | Y | Y |
| 3.1.22 | log_line_prefix has %m%p%d%u%a%h | Y | Y | Y | ~ | ~ |
| 3.1.23 | log_statement = ddl or all | Y | Y | Y | Y | Y |
| 3.1.24 | log_timezone set | Y | Y | Y | Y | Y |
| 3.1.25 | log_error_verbosity = verbose | Y | Y | Y | Y | Y |
| 3.1.26 | log_hostname = off | Y | Y | Y | Y | Y |
| 3.1.27 | log_duration = off | Y | Y | Y | Y | Y |
| 3.2 | pgAudit loaded + configured | Y | Y | Y | ~ | ~ |

## Section 4: User Access and Authorization

| Check | What it does | bare-metal | container | zalando | rds | aurora |
|-------|-------------|:---:|:---:|:---:|:---:|:---:|
| 4.1 | postgres user no login shell | Y | X | X | X | X |
| 4.3 | Only one superuser | Y | Y | Y | ~ | ~ |
| 4.4 | Login roles review (manual) | M | M | M | M | M |
| 4.5 | No SECURITY DEFINER funcs | Y | Y | Y | Y | Y |
| 4.6 | DML privileges review (manual) | M | M | M | M | M |
| 4.7 | RLS review (manual) | M | M | M | M | M |
| 4.8 | set_user / role hierarchy | Y | Y | Y | Y | Y |
| 4.10 | Public schema no CREATE | Y | Y | Y | Y | Y |

## Section 5: Connection and Login

| Check | What it does | bare-metal | container | zalando | rds | aurora |
|-------|-------------|:---:|:---:|:---:|:---:|:---:|
| 5.1 | No passwords in ps output | Y | X | X | X | X |
| 5.2 | listen_addresses not * | Y | ~ | ~ | X | X |
| 5.3 | HBA local auth secure | Y | Y | Y | X | X |
| 5.4 | HBA host auth secure | Y | Y | Y | X | X |
| 5.5 | Connection limits set | Y | Y | Y | ~ | ~ |
| 5.6 | Password complexity module | Y | Y | Y | Y | Y |
| 5.7 | Auth timeout + auth_delay | Y | Y | Y | ~ | ~ |
| 5.8 | SSL for all host conns | Y | Y | Y | X | X |
| 5.9 | CIDR ranges minimized | Y | Y | Y | X | X |
| 5.10 | Specific db/user in HBA | Y | Y | Y | X | X |
| 5.11 | Superuser local only | Y | Y | Y | X | X |
| 5.12 | password_encryption scram | Y | Y | Y | Y | Y |

## Section 6: PostgreSQL Settings

| Check | What it does | bare-metal | container | zalando | rds | aurora |
|-------|-------------|:---:|:---:|:---:|:---:|:---:|
| 6.2 | Backend params secure | Y | Y | Y | Y | Y |
| 6.3 | Postmaster params (manual) | M | M | M | M | M |
| 6.4 | SIGHUP params (manual) | M | M | M | M | M |
| 6.5 | Superuser params (manual) | M | M | M | M | M |
| 6.6 | User params (manual) | M | M | M | M | M |
| 6.7 | FIPS mode enabled | Y | X | X | X | X |
| 6.8 | SSL + TLS 1.2+ | Y | Y | Y | ~ | ~ |
| 6.9 | Crypto extension (manual) | M | M | M | M | M |
| 6.10 | SSL ciphers strong only | Y | Y | Y | ~ | ~ |
| 6.11 | Data anonymization ext | Y | Y | Y | Y | Y |

## Section 7: Replication

| Check | What it does | bare-metal | container | zalando | rds | aurora |
|-------|-------------|:---:|:---:|:---:|:---:|:---:|
| 7.1 | Dedicated replication user | Y | Y | Y | ~ | X |
| 7.2 | log_replication_commands = on | Y | Y | Y | Y | Y |
| 7.4 | WAL archiving configured | Y | Y | Y | X | X |
| 7.5 | primary_conninfo uses SSL | Y | Y | Y | X | X |

## Section 8: Special Configuration

| Check | What it does | bare-metal | container | zalando | rds | aurora |
|-------|-------------|:---:|:---:|:---:|:---:|:---:|
| 8.2 | pgBackRest configured | Y | Y | X | X | X |
| 8.3 | External file/program review | M | M | M | M | M |

## Details on `~` (platform-specific behavior needed)

| Check | What differs |
|-------|-------------|
| 3.1.2 | RDS/Aurora: `log_destination` is `stderr` (managed), not `csvlog`. |
| 3.1.3 | container/zalando: `logging_collector=off` acceptable (logs to stdout/container runtime). RDS/Aurora: always off (managed). |
| 3.1.4/5/6 | Only relevant when `logging_collector=on`. Skip on RDS/Aurora. |
| 3.1.22 | RDS/Aurora set their own `log_line_prefix` format with different tokens. |
| 3.2 | RDS/Aurora: pgAudit loaded via parameter groups; `shared_preload_libraries` may not be visible to non-superuser. Check `pg_extension` instead. |
| 4.3 | RDS/Aurora: `rdsadmin` is a built-in superuser and should be excluded from the count. |
| 5.2 | container/zalando: `listen_addresses='*'` is expected (network policy controls access). RDS/Aurora: managed, not configurable. |
| 5.5 | RDS/Aurora: built-in roles (`rdsadmin`, `rds_replication`) should be excluded. |
| 5.7 | RDS/Aurora: `auth_delay` not available as a preload library. Check only `authentication_timeout`. |
| 6.8 | RDS/Aurora: SSL managed by AWS; `ssl_min_protocol_version` may not be configurable. |
| 6.10 | RDS/Aurora: cipher list managed by AWS. |
| 7.1 | RDS: `rds_replication` role exists as the dedicated replication mechanism. Aurora: no physical replication. |
