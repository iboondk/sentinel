# ADR-0004: Elastic stack for the log demo, local only, security disabled

- Status: accepted
- Date: 2026-10-11

## Context

The project shows how application logs reach a search and dashboard tool. Elastic 8.x with Filebeat and Kibana is a common stack, and its Docker images are easy to run on one machine. Turning on Elastic security needs certificates and users, which add setup steps that are not the point of the demo.

## Decision

- Pin Elasticsearch, Kibana and Filebeat to one version, set by `ELASTIC_VERSION` (default 8.15.3).
- Run Elasticsearch as a single node with `xpack.security.enabled=false`.
- Bind every published port to `127.0.0.1`, so nothing listens on the LAN.
- Mount the fixed app's log volume read-only into Filebeat.
- Put Wazuh behind the `wazuh` compose profile, so it only starts when asked.

## Consequences

- `docker compose up` starts the stack with no certificates or passwords to set up.
- Anyone who can reach the host's loopback interface can read the logs. That is acceptable for a local demo only. The threat model (`docs/threat-model.md`, assumption A-4) says so, and the README tells the reader not to expose these ports.
- Enabling security is listed as required before any shared use.
- Tests check that every published port starts with `127.0.0.1:` and that the images stay pinned. They do not start the stack, because Docker is not available in the development environment.
