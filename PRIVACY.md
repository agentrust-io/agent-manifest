# Privacy

Agent Manifest processes the configuration, identities, keys, and evidence you supply. A manifest can expose metadata such as agent identifiers, artifact locations, and approval identities. Review its contents before publishing or sending it to another party.

Local signing operates on your supplied inputs. The package does not send project telemetry or analytics. Hosted verification endpoints, integrations, and configured attestation providers have their own data flows; a local signature operation does not establish that the surrounding application is offline.

Uninstalling the package does not delete generated manifests, exported keys, revocation lists, logs, backups, or copies already shared with recipients. Manage those artifacts through your application's retention and deletion procedures.

[Report a correction](https://github.com/agentrust-io/agent-manifest/issues).
