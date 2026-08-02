# Phase 5h.48: LocalService authorize schema (deny-only)

Adds a bounded authorize-request schema for future LocalService pipe apply
requests and a native `--self-test-authorize-schema` stdin probe. Valid schemas
still return `authorization_denied=true` with `manifest_executor_absent=true`.
No mutation, vault, or network surface is activated.
