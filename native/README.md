# Native adapters

This directory contains the in-progress Linux adapter and private safety
foundations. The standalone Linux binary accepts `--help`, `--version`,
`validate-inputs`, `verify-report`, and explicit `collect --allow-live-lab`.
The collect path revalidates authority, launches owned workers and publishes a
verified report. Its four core collectors have offline tests; Debian VM native
acceptance is still open. The library bootstrap remains unavailable.

Under the [Linux-first roadmap](../docs/reference/linux-first-roadmap.md), revised Version 5
will implement `native/linux/` using the shared collector/policy interfaces.
Distribution-specific service/log facilities stay behind small typed adapters.
Windows operational work is outside the active roadmap (ADR-0023). Pure input
and report checks do not designate a VM or validate real forensic facts.
