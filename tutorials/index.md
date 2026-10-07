# Tutorials

These step-by-step guides are for developers and operators putting Agent Manifest to work. Start by signing a sample agent record on your own computer and seeing what happens when it changes. Then pick the guide for the job in front of you, such as checking requests on a server or withdrawing a record.

The [first-manifest example](https://manifest.agentrust-io.com/getting-started/index.md) creates the signed record, keys and approved values that several later guides build on. Those pages say where to add their code. The hardware and cMCP guides list the extra setup and checks they need.

______________________________________________________________________

## Getting started

| Tutorial                                                                                          | What you'll build                                                                                                         |
| ------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| [Your first manifest](https://manifest.agentrust-io.com/tutorials/your-first-manifest/index.md)   | A signed Agent Manifest from scratch, with a new signing key and a command line check                                     |
| [CI/CD signing](https://manifest.agentrust-io.com/tutorials/ci-cd-signing/index.md)               | Scripts that sign and check manifests in your build pipeline, plus a workflow that runs when a manifest changes on `main` |
| [cMCP session binding](https://manifest.agentrust-io.com/tutorials/cmcp-session-binding/index.md) | How to set up cMCP (a gateway that records an agent's tool calls) and what its identity evidence means                    |

## Development

| Tutorial                                                                                                           | What you'll build                                                                                                                   |
| ------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------- |
| [Server-side manifest verification](https://manifest.agentrust-io.com/tutorials/server-side-verification/index.md) | A check in front of your server that lets matching requests through and turns away missing, unknown or changed ones                 |
| [A2A delegation chains](https://manifest.agentrust-io.com/tutorials/delegation-chains/index.md)                    | One agent handing work to another and then a third, with less permission at each step, and a check of the whole chain               |
| [HITL approval workflows](https://manifest.agentrust-io.com/tutorials/hitl-approval-workflows/index.md)            | A sample human sign-off (human in the loop, HITL) signed with a software key, and rejection of missing or altered sign-offs         |
| [Revocation and key rotation](https://manifest.agentrust-io.com/tutorials/revocation-and-key-rotation/index.md)    | Withdrawing a signed manifest, making checkers pick up the change, rejecting withdrawals from untrusted signers, and replacing keys |
| [Hardware attestation](https://manifest.agentrust-io.com/tutorials/hardware-attestation/index.md)                  | A runnable software example, how to choose a hardware provider, and how far each hardware report can be trusted                     |

## Operations

| Tutorial                                                                                                               | What you'll build                                                                                                                    |
| ---------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| [Run a verification service](https://manifest.agentrust-io.com/tutorials/deploying-the-verification-endpoint/index.md) | A small web service that checks manifests, loads its trusted keys and withdrawal list at startup, and can be packaged as a container |
