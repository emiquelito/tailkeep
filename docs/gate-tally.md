# Gate tally

This file records, per rule, every time a gate rejected a deliverable and
what it caught. It is a measurement log, not a design document.

Each entry should say where to see the result, so a reader can check it
instead of taking it on trust: a test file, a script's output, or a
commit that carries the fix. Run `agent-delivery-gates tally --check` to
find an entry that is missing one, or that names a rule id that does not
exist.

| # | Date | Rule | Where to see it | What it caught |
|---|------|------|------|----------------|
