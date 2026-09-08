// SPDX-License-Identifier: MIT
// Copyright 2024-2026 National Payments Corporation of India
//! `ainxt` — the headless CLI binary. A thin shell over [`ainxt_cli::run_cli`]: collect args, read
//! stdin only when it is piped (never block an interactive terminal), run one turn, exit with the
//! CLI's deterministic exit code.

use std::io::{IsTerminal, Read, Write};

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();

    // Read stdin only when it is piped/redirected — reading a live terminal would hang the CLI.
    let mut stdin_buf = String::new();
    if !std::io::stdin().is_terminal() {
        let _ = std::io::stdin().read_to_string(&mut stdin_buf);
    }

    let mut stdout = std::io::stdout();
    let code = ainxt_cli::run_cli(&argv, &stdin_buf, &mut stdout).await;
    let _ = stdout.flush();
    std::process::exit(code);
}
