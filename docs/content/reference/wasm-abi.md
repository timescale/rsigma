---
description: "RSigma WASM ABI: building rsigma-parser and rsigma-eval for wasm32-unknown-unknown, the CI smoke test, and the reserved ABI version 1 contract."
---

# WASM ABI

{{ added "0.19.0" }}

RSigma continuously builds `rsigma-parser` and `rsigma-eval` for `wasm32-unknown-unknown` with default features disabled, and CI instantiates a linked smoke module in a JavaScript-free runtime (Wasmtime). That verifies the crates remain host-neutral and free of JavaScript imports. There is no first-party published `.wasm` artifact and no shipped raw host/guest export surface today.

This page reserves ABI version 1 as the design contract for a possible first-party guest. Downstream wrappers (for example [detection.studio](https://github.com/northsh/detection.studio/tree/main/rsigma-wasm) via `wasm-bindgen`) may use the crates today without implementing this ABI.

## What CI guarantees

- `rsigma-parser` and `rsigma-eval` compile for `wasm32-unknown-unknown` with `--no-default-features`.
- A smoke fixture under `ci/wasm-smoke/` links those crates and exports `run_selftest`, which Wasmtime instantiates in CI.
- The smoke path does not export `alloc`, `parse_rule`, `compile_rule`, `evaluate`, or `version`.

## Reserved ABI 1 design

The following is the reserved ABI 1 contract. It is not implemented by the smoke fixture and must not be treated as a shipped interface.

### Compatibility

`version() -> u32` would return the ABI major version. ABI 1 returns `1`.

Changes within ABI 1 are additive. Existing exports keep their signatures and semantics, existing status codes keep their meanings, and existing JSON fields are never removed or retyped. Hosts must ignore unknown JSON fields and may probe for new exports. A breaking change increments the value returned by `version()`.

### Module and memory model

The module exports one WebAssembly linear memory and uses 32-bit offsets into that memory. Hosts request input storage through `alloc`, copy UTF-8 bytes into the returned range, call an operation, and release the input range through `dealloc`.

Guest-owned result buffers stay valid until the host calls `free_result`. Compiled rule handles stay valid until the module instance is destroyed. Handles are scoped to one module instance and must never be passed to another instance.

All sizes and offsets are unsigned 32-bit values. Zero is the null pointer and an invalid handle.

### Exports

| Export | Signature | Contract |
|--------|-----------|----------|
| `alloc` | `(size: u32) -> u32` | Allocates `size` writable bytes in guest memory. Returns zero on allocation failure. |
| `dealloc` | `(ptr: u32, size: u32)` | Releases an input allocation returned by `alloc`. The pointer and size must match the original allocation. |
| `parse_rule` | `(yaml_ptr: u32, yaml_len: u32) -> u64` | Parses UTF-8 Sigma YAML and returns a packed status/result pair. |
| `validate_rule` | `(yaml_ptr: u32, yaml_len: u32) -> u64` | Parses and validates UTF-8 Sigma YAML and returns a packed status/result pair. |
| `compile_rule` | `(yaml_ptr: u32, yaml_len: u32) -> u32` | Parses and compiles one rule collection. Returns a nonzero rule handle on success and zero on failure. Call `validate_rule` first when structured diagnostics are required. |
| `evaluate` | `(rule_handle: u32, event_json_ptr: u32, event_json_len: u32) -> u64` | Evaluates one UTF-8 JSON event against a compiled rule handle and returns a packed status/result pair. |
| `free_result` | `(handle: u32)` | Releases a result descriptor and its payload. A handle must be freed exactly once. Zero is ignored. |
| `version` | `() -> u32` | Returns the ABI major version. ABI 1 returns `1`. |

ABI 1 intentionally ties compiled-rule lifetime to module-instance lifetime.

### Packed return value

Operations returning `u64` encode the status in the high 32 bits and the result handle in the low 32 bits:

```text
packed = (status << 32) | result_handle
status = packed >> 32
result_handle = packed & 0xffff_ffff
```

The result handle is the address of an eight-byte descriptor in linear memory:

| Descriptor offset | Type | Meaning |
|-------------------|------|---------|
| `0` | `u32` | Pointer to the UTF-8 JSON payload. |
| `4` | `u32` | Payload length in bytes. |

The descriptor fields use WebAssembly's little-endian byte order. The host reads the descriptor, copies or consumes the payload, and calls `free_result(handle)`. The descriptor and payload become invalid immediately after that call.

### Status codes

| Status | Name | Meaning |
|--------|------|---------|
| `0` | `OK` | The operation succeeded. |
| `1` | `INVALID_ARGUMENT` | A pointer, length, or handle is invalid. |
| `2` | `INVALID_UTF8` | An input buffer is not valid UTF-8. |
| `3` | `INVALID_YAML` | Sigma YAML parsing failed. |
| `4` | `VALIDATION_ERROR` | The document parsed but failed validation. |
| `5` | `INVALID_JSON` | Event JSON parsing failed. |
| `6` | `EVALUATION_ERROR` | Evaluation failed after inputs were decoded. |
| `255` | `INTERNAL_ERROR` | An unexpected guest failure occurred. |

Status values are stable within ABI 1. New status codes may be added. Hosts must treat unknown nonzero values as failures and still free any nonzero result handle.

### JSON payloads

Every result payload is a UTF-8 JSON object. Successful payloads use `{"ok":true,"data":...}`. Error payloads use this minimum shape:

```json
{
  "ok": false,
  "error": {
    "code": "invalid_yaml",
    "message": "human-readable diagnostic",
    "details": []
  }
}
```

`code` is a stable machine-readable string, `message` is intended for display, and `details` is an array of structured diagnostics. Operations may add fields. Hosts must ignore fields they do not understand.

### Host call sequence

1. Call `version` and reject unsupported major versions.
2. Call `alloc` for the input, check for zero, and copy the UTF-8 bytes into guest memory.
3. Call the operation and then call `dealloc` for the input allocation.
4. Decode the packed status/result value.
5. If the result handle is nonzero, read its descriptor and JSON payload, then call `free_result` even when the status is nonzero.

### Security requirements

Hosts must bounds-check every guest pointer and length against the current linear-memory size before reading. Hosts must cap input and output sizes, reject integer overflow in `ptr + len`, and instantiate untrusted guests with execution and memory limits. A module instance must not be shared concurrently unless the guest implementation explicitly documents synchronization.

## Relationship to existing wrappers

[detection.studio](https://github.com/northsh/detection.studio/tree/main/rsigma-wasm) demonstrates that `rsigma-parser` and `rsigma-eval` work in browser WASM through `wasm-bindgen`. It validates the underlying portability but does not implement or depend on this raw host/guest ABI.
