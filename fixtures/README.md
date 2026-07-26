# Fixtures — the ground truth

Two applications with the same schema and routes, isolated differently. Every
claim TenantTrace makes about its own accuracy is measured against these.

| | scoping mode | expectation |
| --- | --- | --- |
| `vulnerable_app/` | manual (Mode A) | every hole in `labels.yaml` must be found |
| `safe_app/` | global (Mode B) | zero findings — including the intentional admin endpoint |

`labels.yaml` is the answer key: each entry names a location, a severity, and
which engine should catch it. `make metrics` scores the tool against it and
fails the build below 90% recall.

## Warning

`vulnerable_app` is deliberately insecure. It exists to be exploited. It binds
to loopback, ships a hardcoded fixture JWT secret, and must never run anywhere
reachable from a network you don't control.

## Adding a hole

A new attack module needs a matching pair: the hole in `vulnerable_app`, the
correct behaviour in `safe_app`, and both recorded in `labels.yaml`. An attack
module with no labelled case can't be measured, so it doesn't count.
