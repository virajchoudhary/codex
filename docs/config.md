# Configuration

For basic configuration instructions, see [this documentation](https://developers.openai.com/codex/config-basic).

For advanced configuration instructions, see [this documentation](https://developers.openai.com/codex/config-advanced).

For a full configuration reference, see [this documentation](https://developers.openai.com/codex/config-reference).

## Lifecycle hooks

### Legacy notify payload transport

The top-level `notify` command receives its completion-event JSON as the final
argument by default. Set `notify_payload_transport = "stdin"` to write the same
JSON as UTF-8 bytes to the child's standard input instead:

```toml
notify = ["path/to/helper", "--quiet"]
notify_payload_transport = "stdin"
```

The stdin consumer must read through EOF; Codex adds no newline. The payload is
not copied into arguments or environment variables. Codex bounds the write to
five seconds and kills and reaps the direct child if the write fails or times
out. A successful write confirms only pipe delivery, not consumer
acknowledgement, process exit, or downstream notification delivery. The default
`"argv"` transport preserves the legacy invocation.

Admins can set top-level `allow_managed_hooks_only = true` in
`requirements.toml` to ignore user, project, and session hook configs while
still allowing managed hooks from requirements and managed config layers. This
setting is only supported in `requirements.toml`; putting it in `config.toml`
does not enable managed-hooks-only mode.
