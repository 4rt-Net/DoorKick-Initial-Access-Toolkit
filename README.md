# DoorKick

**DoorKick** is a modular initial-access validation toolkit built for **authorized security assessments**. It brings a collection of focused service and application checks into a single Python CLI, making it easier to validate common exposure, authentication, configuration, and remotely reachable attack-surface issues during penetration tests and internal security reviews.

> **Use responsibly:** DoorKick is intended only for systems you own or have explicit permission to test. Several modules perform active validation and may authenticate to services or send security-testing probes.

## What it does

DoorKick dynamically loads assessment modules from the `modules/` directory and lets you run them individually, interactively, or as a full validation pass against a target.

The toolkit currently includes checks for:

- Web and application platforms
- Databases and data services
- Remote administration protocols
- Infrastructure and network services
- Weak/default authentication
- Unauthenticated service exposure
- Security-control and configuration validation
- WordPress REST batch route-confusion / SQL injection exposure via the WP2Shell module

Each module reports findings through a common status system so results are easier to review during an engagement.

## Included modules

| Module | Default service / port | Purpose |
|---|---:|---|
| Apache Tomcat | 8080 | Tomcat exposure and authentication/security validation |
| RDP Security | 3389 | RDP security posture and protocol checks |
| JBoss | 8080 | JBoss exposure and security checks |
| Cassandra No Auth | 9042 | Unauthenticated Cassandra access validation |
| Cisco Smart Install | 4786 | Cisco Smart Install exposure checks |
| CouchDB Security | 5984 | CouchDB exposure, authentication, and version checks |
| Docker Daemon | 2375 | Exposed Docker API validation |
| Elasticsearch RCE | 9200 | Elasticsearch unauthenticated access and execution-risk validation |
| FTP Default Creds | 21 | Anonymous/default FTP authentication checks |
| Network Exposure | Multiple | Commonly exposed management and network services |
| Hadoop YARN RCE | 8088 | YARN ResourceManager exposure and access validation |
| Jenkins Script Console | 8080 | Jenkins exposure and script-console access validation |
| Jupyter Notebook | 8888 | Unauthenticated Jupyter access checks |
| Kubernetes API | 6443 | Kubernetes API unauthenticated access validation |
| LDAP Anonymous Bind | 389 | Anonymous LDAP bind and directory exposure checks |
| MongoDB No Auth | 27017 | Unauthenticated MongoDB access validation |
| MSSQL Default SA | 1433 | MSSQL default/blank `sa` credential validation |
| MySQL Default Creds | 3306 | MySQL weak/default credential validation |
| NFS Exports | 2049 | NFS export exposure checks |
| RDP NLA Check | 3389 | Network Level Authentication enforcement validation |
| Redis Unauth RCE | 6379 | Unauthenticated Redis command-access validation |
| SMB Null Session | 445 | SMB null-session and guest-access checks |
| SNMP Communities | 161 | Default SNMP community validation |
| Spring Boot Actuator | 8080 | Exposed Spring Boot Actuator endpoint checks |
| SSH Default Credentials | 22 | Weak/default SSH credential validation |
| Telnet Auth Bypass | 23 | Telnet authentication posture checks |
| WebLogic | 7001 | WebLogic exposure and security checks |
| WP2Shell SQLi Check | HTTP/HTTPS | WordPress detection and REST batch route-confusion validation |

## Project structure

```text
DoorKick-wp2shell/
├── DoorKick.py              # Main launcher and CLI
├── requirements.txt         # Python dependencies
├── modules/                 # Dynamically loaded assessment modules
│   ├── base_module.py       # Shared module interface/helpers
│   ├── wp2shell.py          # WordPress WP2Shell validation module
│   └── ...
└── utils/
    ├── colors.py            # Terminal styling and status output
    └── helpers.py           # Shared utility functions
```

## Installation

### 1. Clone the repository

```bash
git clone <your-repository-url>
cd DoorKick-wp2shell
```

### 2. Create a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Python dependencies

```bash
python3 -m pip install --upgrade pip
pip install -r requirements.txt
```

Core dependencies currently include `colorama`, `paramiko`, `impacket`, `cassandra-driver`, `pymongo`, `pysnmp`, `pymysql`, and `ldap3`.

Some modules can also make use of optional operating-system utilities such as `showmount`, `ssh`/`sshpass`, or `snmpget` when available.

## Usage

### Interactive mode

Start DoorKick and enter a target when prompted:

```bash
python3 DoorKick.py
```

Or provide the target up front:

```bash
python3 DoorKick.py -t 192.0.2.10
```

The interactive menu lets you select a single module or run the full module set.

### List available modules

```bash
python3 DoorKick.py --list
```

### Run a specific module

First list the module numbers:

```bash
python3 DoorKick.py --list
```

Then run the required module against an authorized target:

```bash
python3 DoorKick.py -t 192.0.2.10 -m <module-number>
```

### Run all modules

```bash
python3 DoorKick.py -t 192.0.2.10 --all
```

`--all` runs modules sequentially. Because several checks perform active validation, use this mode only where the full test scope has been approved.

## WP2Shell module

The WP2Shell module is integrated into DoorKick as a WordPress-specific validation workflow. It performs the assessment in stages:

1. Resolves a reachable HTTP/HTTPS endpoint.
2. Detects WordPress using public markers and version hints.
3. Performs a route-confusion marker check against the REST batch interface.
4. If suspicious behavior is confirmed, asks for explicit operator approval before performing active SQL-injection confirmation.

The module probes common WordPress web ports including `443`, `80`, `8443`, `8080`, `8000`, and `8888` when a hostname or IP address is supplied.

## Result statuses

DoorKick uses common result labels across modules, including:

- `INFO` - informational observation
- `POTENTIAL` - possible exposure requiring validation
- `SUSPECTED` - indicators are present but confirmation is incomplete
- `CONFIRMED` - a validation condition was positively confirmed
- `VULNERABLE` - a security weakness was validated
- `MITIGATED` / `PROTECTED` - the tested condition appears to be blocked or remediated
- `ERROR` - the module could not complete its validation

When leaving the interactive menu normally, collected findings are written to a timestamped text file in the current directory using the format:

```text
doorkick_<target>_<timestamp>.txt
```

Command-line module runs also display results directly in the terminal.

## CLI reference

```text
usage: DoorKick.py [-h] [-t TARGET] [-m MODULE] [-a] [-l]

options:
  -h, --help            show help
  -t, --target TARGET   target IP address or hostname
  -m, --module MODULE   module number to run
  -a, --all             run all modules
  -l, --list            list available modules
```

## Extending DoorKick

DoorKick is designed to be modular. Assessment modules live under `modules/` and inherit from the shared `BaseModule` class. The launcher discovers compatible modules automatically at startup, so new checks can be added without hard-coding them into the main menu.

A module generally defines:

- A human-readable module name
- A default service port where applicable
- A `run()` method containing the validation workflow
- Calls to the shared logging interface for standardized results

This keeps the launcher small while allowing individual checks to evolve independently.

## Operational notes

- Run DoorKick from a controlled assessment host.
- Confirm scope before using credential-validation or active-confirmation modules.
- Prefer testing against staging or lab systems where possible before running broad checks in production.
- Treat findings as validation evidence, not as a replacement for manual review.
- Review service logs and monitoring alerts when assessing production environments, as active checks may be visible to defensive controls.

## Legal and ethical use

DoorKick is provided for legitimate security testing, defensive validation, research, and education. Do not use it against systems without explicit authorization.

The operator is responsible for ensuring that all testing complies with the agreed assessment scope, applicable laws, and organizational policy.

---

**DoorKick v1.0**  
*"Kicking in the digital door"*
