use std::process::Command;

use anyhow::{anyhow, Result};

/// Run cmd in shell and return stdout
pub(crate) fn run_cmd(cmd: &str, args: &[&str]) -> Result<String> {
    let rtn = Command::new(cmd).args(args).output()?;

    if !rtn.status.success() {
        let stderr = std::str::from_utf8(&rtn.stderr).expect("utf8").to_string();

        return Err(anyhow!(format!(
            "Failed to execute command '{}' with args '{:?}'. Exit code is {}, stderr: {}",
            cmd,
            args,
            rtn.status.code().unwrap(),
            stderr,
        )));
    }

    let stdout = std::str::from_utf8(&rtn.stdout).expect("utf8").to_string();

    Ok(stdout)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_run_cmd() {
        let stdout = run_cmd("echo", &["Hello, world!"]).unwrap();
        assert_eq!(stdout, "Hello, world!\n");
    }
}
