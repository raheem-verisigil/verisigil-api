

## CI evidence rule (2026-11-14)

A deployment marked SUCCESS is not a test result. A test file existing is not a passing result. A test is marked TESTED only when the CI run for the exact commit records the Python 3.12 environment, dependency installation, source compilation, each focused security test group, complete unit-test discovery, raw output, exit codes, commit SHA and workflow run URL.

The current Terry scenario replaces the durable receipt adapter with an in-memory fake. A passing Terry scenario therefore validates the tested decision flow against that fake; it does not prove live Supabase API persistence, process-restart recovery, or two-instance concurrency. Those require separate integration tests.
