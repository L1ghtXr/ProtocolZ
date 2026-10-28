ProtocolZ

<p align="center">
  <strong>Modular Network Security Toolkit</strong>
  <br />
  Policy-driven firewall management, security event logging, and a foundation for future network protection.
  <br /><br />
  <a href="https://github.com/L1ghtXr/ProtocolZ/actions/workflows/ci.yml"><img src="https://github.com/L1ghtXr/ProtocolZ/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI Status" /></a>
  <img src="https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white" alt="Python 3.10+" />
  <img src="https://img.shields.io/badge/Platform-Linux-FCC624?logo=linux&logoColor=black" alt="Linux" />
  <img src="https://img.shields.io/badge/Firewall-nftables-blue" alt="nftables" />
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="MIT License" />
  <img src="https://img.shields.io/badge/Status-Early%20Development-orange" alt="Early Development" />
</p><p align="center">
  <em>One modular foundation for network security, built with explicit policies, validation, and recoverability in mind.</em>
</p>---

Overview

ProtocolZ is an open-source network security project focused on building a modular foundation for firewall policy management, security event logging, and future network protection capabilities.

The project currently includes a Python-based nftables integration designed to validate firewall policies, render rules, perform syntax checks, and provide a confirmation-or-rollback workflow when applying managed firewall changes.

ProtocolZ is being developed toward a broader security platform that may eventually include centralized management, service health monitoring, reverse-proxy protection, provider integrations, and Minecraft server protection.

The project is in early development. The existing firewall module is implemented and unit-tested, but real-kernel integration testing and several planned components remain incomplete.

Key highlights

- Policy-driven firewall management — validate structured firewall policies before rendering rules.
- Pre-apply validation — use "nft -c" to check generated rules before applying them.
- Managed ruleset recovery — snapshot the managed ruleset and provide a confirmation-or-rollback workflow.
- Security event logging — record firewall events in JSON Lines format with restrictive file permissions.
- Minimal Python dependencies — the current firewall module uses the Python standard library.
- Automated CI — a GitHub Actions workflow is configured to run project checks.
- Modular architecture — separate directories provide room for future services and integrations.

«Important: ProtocolZ is not a complete security platform yet. Do not treat it as a replacement for a properly configured firewall, access controls, monitoring, backups, or an incident-response plan.»

Project status

Component| Status| Details
nftables firewall| Implemented; unit-tested| Policy validation, rule rendering, syntax-check integration, snapshot, confirmation and rollback logic
Security event log| Partially implemented| Firewall events in JSON Lines format; mode "0600"
Control plane| Not started| Authentication, assets and provider management
Reverse-proxy protection| Not started| Rate limiting and Web Shield
Service health monitoring| Not started| A "health_check" hook exists
Dashboard| Not started| Web-based management interface
Minecraft Game Shield| Not started| Planned game-server security integration
Provider adapters| Not started| Planned external provider integrations
Detection system| Not started| Planned detection capabilities
Docker development environment| Present; untested| Configuration exists; end-to-end behavior is not verified
GitHub Actions CI| Configured; recent runs succeeded| Green workflow runs do not establish production readiness
Benchmarks| Not available| No benchmark results or performance claims published

Status labels describe the current implementation rather than the intended final architecture. See the relevant "STATUS.md" files for component-specific details.

Architecture

The following diagram illustrates the current implementation and planned direction. It is a conceptual overview, not a claim that all components are operational.

flowchart TB
    POLICY["JSON Firewall Policy"]
    CLI["ProtocolZ Python CLI"]
    VALIDATE["Policy Validation"]
    RENDER["nftables Rule Renderer"]
    CHECK["nft -c Syntax Check"]
    SNAPSHOT["Managed Ruleset Snapshot"]
    APPLY["Apply Managed Rules"]
    RECOVERY["Confirm or Roll Back"]
    EVENTS["Firewall Event Log"]

    POLICY --> CLI
    CLI --> VALIDATE
    VALIDATE --> RENDER
    RENDER --> CHECK
    CHECK --> SNAPSHOT
    SNAPSHOT --> APPLY
    APPLY --> RECOVERY
    APPLY --> EVENTS

    subgraph PLANNED["Planned Components"]
        CONTROL["Control Plane"]
        DASH["Dashboard"]
        WEB["Reverse-Proxy Protection"]
        GAME["Minecraft Game Shield"]
        MON["Health Monitoring"]
    end

    classDef implemented fill:#163b2b,stroke:#37b36b,color:#ffffff
    classDef planned fill:#292929,stroke:#888888,color:#ffffff
    class POLICY,CLI,VALIDATE,RENDER,CHECK,SNAPSHOT,APPLY,RECOVERY,EVENTS implemented
    class CONTROL,DASH,WEB,GAME,MON planned

Repository structure

ProtocolZ/
├── .github/
│   └── workflows/
│       └── ci.yml
├── control-plane/
│   └── STATUS.md
├── dashboard/
│   └── STATUS.md
├── data-plane/
│   └── STATUS.md
├── detection/
│   └── STATUS.md
├── docs/
│   ├── architecture.md
│   ├── benchmarks.md
│   ├── deployment.md
│   └── threat-model.md
├── integrations/
│   ├── minecraft/
│   │   └── STATUS.md
│   ├── nftables/
│   │   ├── protocolz_nft/
│   │   │   ├── __init__.py
│   │   │   ├── __main__.py
│   │   │   ├── cli.py
│   │   │   ├── events.py
│   │   │   ├── manager.py
│   │   │   ├── policy.py
│   │   │   └── render.py
│   │   └── README.md
│   └── providers/
│       └── STATUS.md
├── tests/
│   ├── test_nft_cli.py
│   ├── test_nft_manager.py
│   ├── test_nft_policy.py
│   └── test_nft_render.py
├── .env.example
├── docker-compose.yml
├── Makefile
├── README.md
└── SECURITY.md

Some directories currently contain status documentation rather than working implementations.

Requirements

For the current nftables module:

- Python 3.10 or newer.
- Linux for real firewall operations.
- "nft" from the nftables package for syntax checking and firewall management.
- Root privileges for operations that modify the system firewall.
- A test environment and an independent recovery path before applying firewall changes remotely.

The current Python module has no third-party Python package dependencies.

Quick start

1. Clone the repository

git clone https://github.com/L1ghtXr/ProtocolZ.git
cd ProtocolZ

2. Run unit tests

make test

The current test suite is documented as containing 33 standard-library "unittest" tests.

Passing unit tests does not establish that generated rules work correctly against every Linux kernel, nftables version, network configuration, or firewall environment.

3. Prepare a firewall policy

Create a file named "policy.json":

{
  "management_cidrs": [
    "YOUR_REAL_ADMIN_IP/32"
  ],
  "services": [
    {
      "name": "mc-java",
      "proto": "tcp",
      "port": 25565,
      "new_conn_rate": 100
    },
    {
      "name": "mc-bedrock",
      "proto": "udp",
      "port": 19132,
      "new_conn_rate": 200
    }
  ]
}

Replace "YOUR_REAL_ADMIN_IP/32" with your actual management IP or appropriate trusted management CIDR before use. The value above is a placeholder, not valid policy input.

The example ports are illustrative Minecraft Java and Bedrock service ports. Change them to match your environment.

Do not apply a sample policy to a production host without reviewing the rendered rules and confirming that management access will remain available.

4. Set the Python module path

From the repository root:

export PYTHONPATH=integrations/nftables

5. Validate and render

python3 -m protocolz_nft validate policy.json
python3 -m protocolz_nft render policy.json

Review the output and confirm that the policy matches your intended network configuration.

6. Run a syntax-only dry run

On a Linux test host with "nft" installed:

sudo python3 -m protocolz_nft dry-run policy.json

The dry-run path uses "nft -c" to check the generated rules. A syntax check does not prove that the firewall will behave as intended under real traffic.

7. Apply only in a controlled environment

The CLI currently documents the following commands:

sudo python3 -m protocolz_nft apply --yes policy.json
sudo python3 -m protocolz_nft confirm
sudo python3 -m protocolz_nft rollback --yes

These are examples of the available command interface, not a recommendation to execute them blindly.

Before applying:

1. Inspect the generated rules.
2. Test on a disposable Linux VM or isolated host.
3. Ensure you have console access independent of SSH.
4. Verify the actual confirmation and rollback behavior of the installed version.
5. Understand which existing rules will be replaced.

The apply workflow has a confirmation window documented as 60 seconds. Confirmation and rollback must be tested on the target environment before relying on them for recovery.

Firewall safety model

ProtocolZ's current nftables module is designed around explicit policy validation and controlled changes.

Management access is mandatory

The policy requires "management_cidrs". This is intended to prevent building a policy that omits the administrator's management network.

However, the presence of a CIDR in a policy does not guarantee connectivity. Routing, existing firewall rules, SSH configuration, cloud security groups, and the actual generated rules must also be checked.

Validation before application

The workflow performs an "nft -c" syntax check before applying the managed ruleset.

This helps catch syntax errors. It does not replace real-kernel integration tests or behavioral testing.

Managed ruleset scope

The current design replaces the "inet protocolz" table and manages its input hook. Other tables, including Docker-managed tables, are intended to remain untouched.

Inspect the generated rules and the implementation before relying on this boundary in a production environment.

Snapshot and recovery

The implementation includes a snapshot and confirmation-or-rollback workflow. The documented confirmation window is 60 seconds.

Do not assume recovery is guaranteed if the SSH session, foreground process, host, or operating system fails. The current implementation has a foreground confirmation dependency, and process termination can affect the recovery workflow. Test failure scenarios explicitly before remote use.

Rate limiting: current limitations

The current rate limits are applied per rule and address family, not independently per source IP.

This means a shared rule-level budget can be consumed by traffic from multiple sources. Legitimate new connections may be starved during a flood.

Per-source rate limiting using dynamic sets is planned, not implemented.

Do not interpret the current rate-limit configuration as comprehensive DDoS protection. Upstream filtering, connection management, monitoring, and capacity planning may still be required.

Security event logging

The current event log records firewall-related events in JSON Lines format.

The log file is configured with mode "0600", restricting access according to normal Unix permission semantics.

Current scope and limitations:

- Only firewall events are implemented.
- A complete centralized security event pipeline is not available.
- Log rotation, retention, alerting, and external forwarding should be evaluated for the deployment environment.
- File permissions do not encrypt log contents or prevent access by privileged processes.

Testing and CI

The repository contains unit tests for the nftables CLI, manager, policy validation, and rule rendering.

Run tests locally:

make test

GitHub Actions is configured in ".github/workflows/ci.yml". Recent workflow runs have completed successfully.

""CI Status" (https://github.com/L1ghtXr/ProtocolZ/actions/workflows/ci.yml/badge.svg?branch=main)" (https://github.com/L1ghtXr/ProtocolZ/actions/workflows/ci.yml)

A successful CI run only confirms that the checks defined in the workflow completed successfully. It does not mean every feature is implemented or that the firewall has been validated against a real kernel.

Planned validation improvements

- Integration tests in isolated Linux network namespaces.
- Real-kernel nftables behavior tests.
- Failure-injection tests for rollback and process termination.
- Docker development-environment validation.
- Additional policy edge-case tests.
- Reproducible performance benchmarks.

No benchmark results are currently published.

Roadmap

The following items represent planned work, not current capabilities.

- [x] Implement the initial nftables policy and rendering module.
- [x] Add firewall module unit tests.
- [x] Add a confirmation-or-rollback workflow.
- [x] Add a GitHub Actions CI workflow.
- [ ] Validate nftables behavior in isolated Linux network namespaces.
- [ ] Test rollback under process and connection failure scenarios.
- [ ] Verify the Docker development environment.
- [ ] Implement per-source rate limiting using dynamic sets.
- [ ] Develop service health monitoring.
- [ ] Implement the control plane and authentication.
- [ ] Develop provider adapters and asset management.
- [ ] Implement reverse-proxy rate limiting and Web Shield.
- [ ] Develop the management dashboard.
- [ ] Design and implement Minecraft Game Shield.
- [ ] Publish reproducible benchmarks.

Completion should be based on implementation and testing evidence, not simply on the existence of a directory or status file.

Documentation

Additional documentation is available in the repository:

- "Architecture" (docs/architecture.md)
- "Deployment" (docs/deployment.md)
- "Threat model" (docs/threat-model.md)
- "Benchmarks" (docs/benchmarks.md)
- "nftables integration" (integrations/nftables/README.md)
- "Security policy" (SECURITY.md)
- "Changelog" (CHANGELOG.md)
- "Contribution guidelines" (CONTRIBUTING.md)

Benchmark documentation does not imply that benchmarks have already been executed.

Contributing

Contributions are welcome, particularly in testing, documentation, policy validation, Linux networking, and reliability.

Before contributing:

1. Read "CONTRIBUTING.md" (CONTRIBUTING.md).
2. Review the component status and current limitations.
3. Keep changes focused and testable.
4. Run "make test" when applicable.
5. Clearly document tests that require Linux kernel features, elevated privileges, Docker, or external infrastructure.

Please do not submit fabricated benchmark results or claim production readiness without reproducible evidence.

Reporting security issues

Please review "SECURITY.md" (SECURITY.md) for the project's security-reporting guidance.

Avoid publishing sensitive exploit details or credentials in public issues.

License

ProtocolZ is distributed under the MIT License. See "LICENSE" (LICENSE) for the full terms.

Project links

- Repository: https://github.com/L1ghtXr/ProtocolZ
- Issues: https://github.com/L1ghtXr/ProtocolZ/issues
- Pull requests: https://github.com/L1ghtXr/ProtocolZ/pulls
- GitHub Actions: https://github.com/L1ghtXr/ProtocolZ/actions

---

<p align="center">
  <strong>ProtocolZ</strong>
  <br />
  Open source. Explicit policies. Verifiable progress.
</p>
