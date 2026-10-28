# Contributing

1. `make test` must pass. New behavior needs tests, including failure paths.
2. No new dependencies unless a benchmark or requirement justifies them.
3. Never claim a capability that is not implemented and tested; update the status table in README.
4. Benchmarks must include hardware, method, and limitations. Never estimate or fabricate numbers.
5. Changes that touch live system state need dry-run and rollback paths.
6. No offensive features (see SECURITY.md). Test traffic only against targets you own, with rate caps.
