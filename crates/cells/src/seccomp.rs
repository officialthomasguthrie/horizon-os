// The Cell's syscall filter. seccompiler assembles the BPF for the host arch,
// so the same source filters correctly on x86-64 and aarch64. The filter is
// installed after PR_SET_NO_NEW_PRIVS, which is what lets an unprivileged
// process load it and makes it survive exec.

use std::collections::BTreeMap;

use seccompiler::{BpfProgram, SeccompAction, SeccompFilter};

use crate::error::{Error, Result};

// Allow every syscall except the listed ones, which are refused with EPERM.
// An empty rule vector matches the syscall number unconditionally.
pub(crate) fn apply_block(syscalls: &[i64]) -> Result<()> {
    let arch = std::env::consts::ARCH.try_into().map_err(|e| {
        Error::Seccomp(format!(
            "unsupported arch {}: {e:?}",
            std::env::consts::ARCH
        ))
    })?;

    let mut rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> = BTreeMap::new();
    for &nr in syscalls {
        rules.insert(nr, Vec::new());
    }

    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,                     // default: allow
        SeccompAction::Errno(libc::EPERM as u32), // listed: refuse with EPERM
        arch,
    )
    .map_err(|e| Error::Seccomp(format!("{e:?}")))?;

    let program: BpfProgram = filter
        .try_into()
        .map_err(|e| Error::Seccomp(format!("{e:?}")))?;

    seccompiler::apply_filter(&program).map_err(|e| Error::Seccomp(format!("{e:?}")))?;
    Ok(())
}
