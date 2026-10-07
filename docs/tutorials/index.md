# Tutorials

These step-by-step guides are for developers and operators putting Agent Manifest to work. Start by signing a sample agent record on your own computer and seeing what happens when it changes. Then pick the guide for the job in front of you, such as checking requests on a server or withdrawing a record.

The [first-manifest example](../getting-started.md) creates the signed record, keys and approved values that several later guides build on. Those pages say where to add their code. The hardware and cMCP guides list the extra setup and checks they need.

---

## Getting started

| Tutorial | What you'll build |
|----------|-------------------|
| [Your first manifest](your-first-manifest.md) | A signed Agent Manifest from scratch, with a new signing key and a command line check |
| [CI/CD signing](ci-cd-signing.md) | Scripts that sign and check manifests in your build pipeline, plus a workflow that runs when a manifest changes on `main` |
| [cMCP session binding](cmcp-session-binding.md) | How to set up cMCP (a gateway that records an agent's tool calls) and what its identity evidence means |

## Development

| Tutorial | What you'll build |
|----------|-------------------|
| [Server-side manifest verification](server-side-verification.md) | A check in front of your server that lets matching requests through and turns away missing, unknown or changed ones |
| [A2A delegation chains](delegation-chains.md) | One agent handing work to another and then a third, with less permission at each step, and a check of the whole chain |
| [HITL approval workflows](hitl-approval-workflows.md) | A sample human sign-off (human in the loop, HITL) signed with a software key, and rejection of missing or altered sign-offs |
| [Revocation and key rotation](revocation-and-key-rotation.md) | Withdrawing a signed manifest, making checkers pick up the change, rejecting withdrawals from untrusted signers, and replacing keys |
| [Hardware attestation](hardware-attestation.md) | A runnable software example, how to choose a hardware provider, and how far each hardware report can be trusted |

## Operations

| Tutorial | What you'll build |
|----------|-------------------|
| [Run a verification service](deploying-the-verification-endpoint.md) | A small web service that checks manifests, loads its trusted keys and withdrawal list at startup, and can be packaged as a container |
