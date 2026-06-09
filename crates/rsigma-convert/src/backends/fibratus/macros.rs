//! Fibratus macro library, used by Phase 3 to rewrite recognized condition
//! AST sub-trees into idiomatic macro calls (`spawn_process`, `open_file`,
//! `modify_registry`, ...).
//!
//! The expression text on the right of each entry is the canonical form
//! upstream ships in [`rules/macros/macros.yml`](https://github.com/rabbitstack/fibratus/blob/master/rules/macros/macros.yml).
//! Recognition compares parsed [`rsigma_parser::ConditionExpr`] sub-trees
//! against the parsed AST of these strings, so whitespace and operand
//! ordering on the rendered query do not affect matching.

/// Macro entry: `(macro_name, canonical_expression_text)`.
///
/// Only the leaves that reduce to a single boolean expression are listed
/// here. List-style macros (e.g. `msoffice_binaries`, `script_interpreters`)
/// are emitted by their literal name when an in-list comparison happens to
/// match the same value sequence; that is handled in Phase 3 with a
/// separate list-recognition pass.
pub const EXPRESSION_MACROS: &[(&str, &str)] = &[
    ("spawn_process", "evt.name = 'CreateProcess'"),
    ("create_thread", "evt.name = 'CreateThread'"),
    (
        "create_remote_thread",
        "evt.name = 'CreateThread' and evt.pid != 4 and evt.pid != thread.pid",
    ),
    (
        "open_process",
        "evt.name = 'OpenProcess' and ps.access.status = 'Success'",
    ),
    (
        "open_thread",
        "evt.name = 'OpenThread' and thread.access.status = 'Success'",
    ),
    ("write_file", "evt.name = 'WriteFile'"),
    (
        "open_file",
        "evt.name = 'CreateFile' and file.operation = 'OPEN' and file.status = 'Success'",
    ),
    (
        "create_file",
        "evt.name = 'CreateFile' and file.operation != 'OPEN' and file.status = 'Success'",
    ),
    (
        "create_new_file",
        "evt.name = 'CreateFile' and file.operation = 'CREATE' and file.status = 'Success'",
    ),
    (
        "create_file_supersede",
        "evt.name = 'CreateFile' and file.operation = 'SUPERSEDE'",
    ),
    ("rename_file", "evt.name = 'RenameFile'"),
    ("read_file", "evt.name = 'ReadFile'"),
    ("delete_file", "evt.name = 'DeleteFile'"),
    ("set_file_information", "evt.name = 'SetFileInformation'"),
    (
        "query_registry",
        "evt.name in ('RegQueryKey', 'RegQueryValue') and registry.status = 'Success'",
    ),
    (
        "open_registry",
        "evt.name = 'RegOpenKey' and registry.status = 'Success'",
    ),
    ("load_module", "evt.name = 'LoadModule'"),
    ("unload_module", "evt.name = 'UnloadModule'"),
    (
        "set_value",
        "evt.name = 'RegSetValue' and registry.status = 'Success'",
    ),
    (
        "create_key",
        "evt.name = 'RegCreateKey' and registry.status = 'Success'",
    ),
    ("send_socket", "evt.name = 'Send'"),
    ("recv_socket", "evt.name = 'Recv'"),
    ("connect_socket", "evt.name = 'Connect'"),
    ("accept_socket", "evt.name = 'Accept'"),
    ("virtual_alloc", "evt.name = 'VirtualAlloc'"),
    ("virtual_free", "evt.name = 'VirtualFree'"),
    ("map_view_file", "evt.name = 'MapViewFile'"),
    ("unmap_view_file", "evt.name = 'UnmapViewFile'"),
    ("duplicate_handle", "evt.name = 'DuplicateHandle'"),
    ("create_handle", "evt.name = 'CreateHandle'"),
    ("query_dns", "evt.name = 'QueryDns'"),
    ("reply_dns", "evt.name = 'ReplyDns'"),
];

/// Macro name lookup: is this name a known Fibratus expression macro?
///
/// Used to avoid emitting collisions when a user's detection name happens
/// to share a macro identifier.
pub fn is_known_macro(name: &str) -> bool {
    EXPRESSION_MACROS.iter().any(|(n, _)| *n == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_macro_lookup() {
        assert!(is_known_macro("spawn_process"));
        assert!(is_known_macro("create_remote_thread"));
        // Composite macros (`modify_registry`, `inbound_network`,
        // `outbound_network`, `load_driver`, `load_unsigned_module`, ...)
        // upstream defines on top of other macros are intentionally absent
        // from the leaf table; Phase 3 recognizes them in a separate pass.
        assert!(!is_known_macro("modify_registry"));
        assert!(!is_known_macro("not_a_macro"));
    }
}
