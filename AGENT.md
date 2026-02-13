---
# Cartouche v1
title: "c-holons - Agent Directives"
author:
  name: "B. ALTER"
  copyright: "© 2026 Benoit Pereira da Silva"
created: 2026-02-12
revised: 2026-02-12
lang: en-US
origin_lang: en-US
translation_of: null
translator: null
access:
  humans: true
  agents: true
status: draft
---

# c-holons - Agent Directives

`c-holons` is not a holon. It is a C SDK that mirrors the Go reference surface:
- transport parsing and listener lifecycle
- serve loop and flag parsing
- HOLON identity parsing

Read the repository constitution first: `/Users/bpds/Documents/Entrepot/Git/Compilons/videosteno/organic-programming/AGENT.md`.

## Structure

```
sdk/c-holons/
├── AGENT.md
├── README.md
├── include/holons/holons.h
├── src/holons.c
└── test/holons_test.c
```

## Public API contract

Use only `include/holons/holons.h` from consumers.

Stable primitives:
- `holons_parse_flags`
- `holons_parse_uri`
- `holons_listen` / `holons_accept` / `holons_close_listener`
- `holons_mem_dial`
- `holons_serve`
- `holons_parse_holon`

## Transport semantics

Required schemes from Article 11:
- `tcp://`
- `stdio://`

Optional schemes:
- `unix://`
- `mem://`
- `ws://`
- `wss://`

Important:
- In this C SDK, `ws://` and `wss://` are currently implemented at socket URI/listener level.
- They do not implement full RFC6455 WebSocket handshake/framing in-process.
- If full browser-compatible WebSocket transport is needed, run behind a WS bridge/proxy.

## Editing directives

When modifying `src/holons.c`:
1. Keep dependencies limited to libc + POSIX; do not introduce external runtime dependencies.
2. Preserve deterministic behavior for parsing and listener lifecycle.
3. Keep `stdio://` and `mem://` single-connection semantics explicit.
4. Keep error messages actionable and transport-specific.
5. Update tests in `test/holons_test.c` for every behavior change.

## Build and test

From `/Users/bpds/Documents/Entrepot/Git/Compilons/videosteno/organic-programming/sdk/c-holons`:

```bash
clang -std=c11 -Wall -Wextra -pedantic -I include src/holons.c test/holons_test.c -o test_runner
./test_runner
```

Sandbox note:
- In restricted environments, socket bind tests (tcp/unix/ws/wss) may be skipped.
- This is expected and does not invalidate parser or in-process transport coverage.
