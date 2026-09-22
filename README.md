# mos_crac


> Active development has moved to Azul's internal GitLab:
> `gitlab.azulsystems.com/isukhanov/warp-macos`. This GitHub
> copy is no longer the primary repo.

Proof-of-concept macOS-native checkpoint/restore engine for OpenJDK's
[CRaC](https://docs.azul.com/crac) — a Warp/minicriu analogue for Darwin.

CRaC lets a JVM checkpoint its warmed-up state and restore from it later,
skipping startup/warmup cost. On Linux, the [Warp/minicriu](https://foojay.io/today/warp-the-new-crac-engine)
engine does the actual checkpoint/restore: the process triggers a real kernel
core dump on itself, then re-execs and reparses that dump to lay memory back
out and resume. This project researches and prototypes the macOS equivalent
of that mechanism.

**Current phase:** a standalone checkpoint/restore prototype, independent of
the JVM. Wiring a working mechanism into CRaC's `crlib` SPI (as
`crac_bsd.cpp`) is deferred until this core mechanism works.

## Layout

- `src/` — stable, proven-working capture/restore implementation.
- `tests/` — throwaway probes/experiments, plus supporting build tools.
- `local/`, `tmps/` — local scratch (gitignored).
