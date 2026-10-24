// SPDX-License-Identifier: MIT OR Apache-2.0

//! Reading the execution policy without root (ADR-025 point 1, P2-008b).
//!
//! Astra Linux is the first case: its closed software environment is
//! configured by `DIGSIG_ELF_MODE` in `/etc/digsig/digsig_initramfs.conf`
//! and takes effect after a reboot. The running state needs root
//! (`astra-digsig-control status`, `/sys/module/digsig_verif`), so the
//! configured state is read, and anything that could make the two differ
//! counts as "cannot be ruled out" (R-006, conclusion 4).
//!
//! Other first targets have no execution policy that would refuse files
//! installed by the package manager, so they are `Off`.

use super::ExecutionPolicy;

/// The configuration file of the Astra Linux closed software environment.
pub const ASTRA_DIGSIG_CONF: &str = "/etc/digsig/digsig_initramfs.conf";

/// The value of `DIGSIG_ELF_MODE` in the file, as the shell would read it:
/// the last assignment wins, comments and quotes are ignored.
fn digsig_elf_mode(conf: &str) -> Option<String> {
    let mut value = None;
    for line in conf.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        if let Some(raw) = line.strip_prefix("DIGSIG_ELF_MODE=") {
            let raw = raw.split('#').next().unwrap_or_default().trim();
            value = Some(raw.trim_matches(['"', '\'']).to_owned());
        }
    }
    value.filter(|value| !value.is_empty())
}

/// The Astra Linux closed environment from what an unprivileged process can
/// read. `conf` is the file's content (`None` when missing or unreadable);
/// `changed_since_boot` says whether the file was modified after the
/// current boot (`None` when that cannot be told).
pub fn astra_execution_policy(
    conf: Option<&str>,
    changed_since_boot: Option<bool>,
) -> ExecutionPolicy {
    match conf.and_then(digsig_elf_mode).as_deref() {
        None => ExecutionPolicy::Unknown,
        Some("0") => match changed_since_boot {
            // Configured off, and the running system booted with it.
            Some(false) => ExecutionPolicy::Off,
            // Turned off after boot (still on until a reboot), or unknown.
            _ => ExecutionPolicy::Unknown,
        },
        // Any other mode verifies signatures of executables.
        Some(_) => ExecutionPolicy::On,
    }
}

/// The policy of a system by its `os-release` `ID`.
pub fn execution_policy(
    os_id: &str,
    astra: impl FnOnce() -> (Option<String>, Option<bool>),
) -> ExecutionPolicy {
    if os_id == "astra" {
        let (conf, changed) = astra();
        astra_execution_policy(conf.as_deref(), changed)
    } else {
        ExecutionPolicy::Off
    }
}

/// The boot time from `/proc/stat` (`btime`, seconds since the epoch).
pub fn boot_time(proc_stat: &str) -> Option<u64> {
    proc_stat
        .lines()
        .find_map(|line| line.strip_prefix("btime "))
        .and_then(|value| value.trim().parse().ok())
}

/// Reads the policy of the running Linux system without root.
#[cfg(target_os = "linux")]
pub fn detect() -> ExecutionPolicy {
    use std::fs;
    use std::time::UNIX_EPOCH;

    let os_release = fs::read_to_string("/etc/os-release").unwrap_or_default();
    let id =
        crate::namespace::collect::parse::os_release_value(&os_release, "ID").unwrap_or_default();
    execution_policy(id, || {
        let conf = fs::read_to_string(ASTRA_DIGSIG_CONF).ok();
        let modified = fs::metadata(ASTRA_DIGSIG_CONF)
            .and_then(|metadata| metadata.modified())
            .ok()
            .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
            .map(|duration| duration.as_secs());
        let booted = fs::read_to_string("/proc/stat")
            .ok()
            .as_deref()
            .and_then(boot_time);
        let changed = modified
            .zip(booted)
            .map(|(modified, booted)| modified >= booted);
        (conf, changed)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The keys R-006 recorded in the file on Astra Linux 1.8.6. A similar
    /// key (`DIGSIG_ELF_VERIFICATION_MODE`) must not be read as the mode.
    const OFF: &str = "DIGSIG_ELF_VERIFICATION_MODE=1\nDIGSIG_ELF_MODE=0\nDIGSIG_XATTR_MODE=0\n\
                       DIGSIG_IGNORE_XATTR_KEYS=0\nDIGSIG_IGNORE_GOST2001=0\n";
    const ON: &str = "DIGSIG_ELF_MODE=1\nDIGSIG_ELF_VERIFICATION_MODE=0\nDIGSIG_XATTR_MODE=0\n\
                      DIGSIG_IGNORE_XATTR_KEYS=0\nDIGSIG_IGNORE_GOST2001=0\n";

    #[test]
    fn the_closed_environment_on_is_on() {
        assert_eq!(
            astra_execution_policy(Some(ON), Some(false)),
            ExecutionPolicy::On
        );
        assert_eq!(astra_execution_policy(Some(ON), None), ExecutionPolicy::On);
        assert_eq!(
            astra_execution_policy(Some("DIGSIG_ELF_MODE=2\n"), Some(false)),
            ExecutionPolicy::On
        );
    }

    #[test]
    fn off_only_when_configured_off_before_this_boot() {
        assert_eq!(
            astra_execution_policy(Some(OFF), Some(false)),
            ExecutionPolicy::Off
        );
        // Turned off after boot: the running kernel still verifies.
        assert_eq!(
            astra_execution_policy(Some(OFF), Some(true)),
            ExecutionPolicy::Unknown
        );
        assert_eq!(
            astra_execution_policy(Some(OFF), None),
            ExecutionPolicy::Unknown
        );
    }

    #[test]
    fn a_missing_or_unreadable_indicator_is_never_off() {
        assert_eq!(
            astra_execution_policy(None, Some(false)),
            ExecutionPolicy::Unknown
        );
        assert_eq!(
            astra_execution_policy(Some("DIGSIG_LOAD_KEYS=1\n"), Some(false)),
            ExecutionPolicy::Unknown
        );
        assert_eq!(
            astra_execution_policy(Some("DIGSIG_ELF_MODE=\n"), Some(false)),
            ExecutionPolicy::Unknown
        );
    }

    #[test]
    fn the_file_is_read_as_the_shell_reads_it() {
        let commented = "# DIGSIG_ELF_MODE=0\nDIGSIG_ELF_MODE=1\n";
        assert_eq!(
            astra_execution_policy(Some(commented), Some(false)),
            ExecutionPolicy::On
        );
        let last_wins = "DIGSIG_ELF_MODE=1\nDIGSIG_ELF_MODE=\"0\" # off\n";
        assert_eq!(
            astra_execution_policy(Some(last_wins), Some(false)),
            ExecutionPolicy::Off
        );
        let exported = "export DIGSIG_ELF_MODE='1'\n";
        assert_eq!(
            astra_execution_policy(Some(exported), Some(false)),
            ExecutionPolicy::On
        );
    }

    #[test]
    fn other_distributions_have_no_execution_policy_and_astra_is_always_read() {
        let mut read = false;
        assert_eq!(
            execution_policy("debian", || {
                read = true;
                (None, None)
            }),
            ExecutionPolicy::Off
        );
        assert!(!read);
        assert_eq!(
            execution_policy("astra", || (None, None)),
            ExecutionPolicy::Unknown
        );
    }

    #[test]
    fn the_boot_time_is_read_from_proc_stat() {
        let stat = "cpu  1 2 3\nintr 5\nbtime 1792730000\nprocesses 42\n";
        assert_eq!(boot_time(stat), Some(1_792_730_000));
        assert_eq!(boot_time("cpu 1\n"), None);
    }
}
