// SPDX-License-Identifier: MIT OR Apache-2.0

use std::error::Error;
use std::path::Path;

fn main() -> Result<(), Box<dyn Error>> {
    let mut arguments = std::env::args_os().skip(1);
    let output = arguments.next().ok_or("missing output RPM path")?;
    let binary = arguments.next().ok_or("missing probe binary path")?;
    let binary = binary.to_str().ok_or("probe binary path is not UTF-8")?;
    if arguments.next().is_some() {
        return Err("unexpected extra argument".into());
    }

    let mut builder = rpm::PackageBuilder::new(
        "pakomichi-stack-probe",
        "0.0.0",
        "MIT OR Apache-2.0",
        "x86_64",
        "Disposable Pakomichi P0-004 packaging probe",
    );
    builder
        .release("1")
        .with_file(
            binary,
            rpm::FileOptions::new("/usr/bin/pakomichi-stack-probe").permissions(0o755),
        )?
        .with_file(
            "pakomichi-stack-probe.service",
            rpm::FileOptions::new("/usr/lib/systemd/system/pakomichi-stack-probe.service")
                .permissions(0o644),
        )?
        .with_file(
            "pakomichi-stack-probe.socket",
            rpm::FileOptions::new("/usr/lib/systemd/system/pakomichi-stack-probe.socket")
                .permissions(0o644),
        )?;
    builder.build()?.write_file(&output)?;

    let metadata = rpm::PackageMetadata::open(Path::new(&output))?;
    if metadata.get_name()? != "pakomichi-stack-probe" {
        return Err("RPM name round-trip failed".into());
    }
    if metadata.get_pre_install_script().is_ok() {
        return Err("probe RPM unexpectedly contains a pre-install script".into());
    }
    println!("rpm={}", Path::new(&output).display());
    Ok(())
}
