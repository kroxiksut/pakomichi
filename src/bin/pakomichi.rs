// SPDX-License-Identifier: MIT OR Apache-2.0

//! `pakomichi`: the full command of the Pakomichi CLI (`specifications/cli-api.md`).
//! `pchi` is the same program; both call `pakomichi::cli::main`.

fn main() -> std::process::ExitCode {
    std::process::ExitCode::from(pakomichi::cli::main())
}
