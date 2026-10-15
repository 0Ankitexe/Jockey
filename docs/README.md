# JOCKY documentation

Start with the **[Project and Viva Guide](PROJECT_GUIDE.md)** for the whole
project through Version 5, a short demo, simple terms and an explanation of
every documentation and records file. Use [current-state.md](current-state.md)
for the latest completion and testing status.

## Technical references

| Topic                    | File and purpose                                                                                                                                                       |
| ------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| System design            | [Architecture](reference/architecture.md): component responsibilities and current versus planned paths.                                                                |
| Writing programs         | [Language reference](reference/language-reference.md): `.jky` syntax; [diagnostics](reference/diagnostics.md): errors and exit codes.                                  |
| Functions and targets    | [Module contracts](reference/module-contracts.md): named functions and availability; [platform capabilities](reference/platform-capabilities.md): permitted targets.   |
| Compiler and sample runs | [IR specification](reference/ir-specification.md): checked instruction format; [reference interpreter](reference/reference-interpreter.md): sample-data execution.     |
| Data and safety          | [Result model](reference/cross-platform-result-model.md): identities and reports; [security boundary](reference/security-boundary.md): allowed and forbidden behavior. |
| Native Linux             | [Collector guide](reference/linux-collectors.md): inputs and VM operation; [support matrix](reference/linux-support-matrix.md): what Debian testing actually proved.   |
| Future work              | [Linux-first roadmap](reference/linux-first-roadmap.md): V6–V9 plans, not current capabilities.                                                                        |

These 12 reference pages explain implementation details; they are not copies
of test records. Dated decisions, release checks and original evidence live in
[project-records/](../project-records/README.md). Its index explains the
intermediate V3 checkpoint, final V3 release and V5 release separately.
