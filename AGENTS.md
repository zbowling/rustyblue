# AGENT Instructions

This repository contains a work-in-progress Bluetooth stack written in Rust.
The following rules apply to all modifications:

## Required steps

- Always run `cargo fmt --all` before committing.
- Run `cargo test --workspace --quiet` and ensure the tests pass.
- Summarize the change and test results in the pull request message.
- Keep commit messages concise and descriptive.
- Do **not** mention "Claude" in commits or PRs.

## Code style

- Use Rust 2021 idioms and naming conventions.
- Include documentation comments (`//!` or `///`) for public items.
- When adding HCI features, add unit tests in `crates/rustyblue/src/hci/tests.rs`.
- Mention relevant Bluetooth specification sections in comments when helpful.

## Directory notes

- The main crate is under `crates/rustyblue`. Changes here should be tested with `cargo test`.
- Specification PDFs are in `specs/` for reference only and should not be modified.
- Every directory should have a README.md file that describes the purpose of the directory and its contents.
