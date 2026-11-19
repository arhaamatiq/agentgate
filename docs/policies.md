# Writing policies

A policy says what one agent is allowed to do. Anything outside it is blocked,
or, when genuinely ambiguous, sent to the LLM judge.

```yaml
agents:
  reporting-agent:
    task: Produce the weekly sales report from the analytics database.
    allowed_operations: [read]
    allowed_resources: [sales, orders, products, /reports]
```

The gateway reads this from [`deploy/policy.yaml`](../deploy/policy.yaml). The
Python library takes the same three fields in `agentgate.scope(...)`.

## Operations

An entry in `allowed_operations` can be:

- **A class the engine infers:** `read`, `write`, `send`, `export`, `deploy`,
  `config`, `execute`, `destructive`, `http`.
- **A tool's own verb:** `[delete]` permits `delete_file`, but never
  `write_file` or a SQL `DROP`. A verb only covers the classes it belongs to.
- **A tool's full name:** `[restart_service]` permits that tool.

`destructive` (`DROP`, `TRUNCATE`, `GRANT`, ...) is never implied. It always has
to be declared. `deny_operations` takes the same forms and always wins.

A file tool counts as a `read` only if its name says so (`read_file`,
`list_directory`, `search_files`). `edit_file` or `move_file` is a `write`, and
`send_file` is a `send`, so the recipient checks apply.

A call that only reads passes a `read` scope even when its class differs: a GET
to a URL listed in `allowed_resources`, or a plain diagnostic command such as
`df -h` (nothing chained, piped or redirected).

## Resources

- **Absolute paths** cover that path and what is under it, never its parent or
  a sibling: `/srv/finance/reports` does not allow `/srv` or
  `/srv/finance/reports_old`.
- **URLs** cover themselves and what is under their path, never another host:
  `https://api.example.com` does not allow `https://api.example.com.evil.net`.
- **Names** (tables, services, recipients) match the name and its variants:
  `orders` covers `orders_2024`.

A path inside an allowed resource such as `/var/log/app/` is still checked for
credential files, traversal and encoding tricks. Only location guesses (system
directories, `*.conf`, `backups/`) defer to an explicit grant, and those calls
go to the LLM judge instead of being blocked outright.
