use anyhow::{Context as _, anyhow};
use aya_build::Toolchain;
use std::{ffi::OsString, path::PathBuf, process::Command};

fn main() -> anyhow::Result<()> {
    ensure_frontend_bundle()?;

    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;
    let ebpf_package = packages
        .into_iter()
        .find(|cargo_metadata::Package { name, .. }| name.as_str() == "snitch-ebpf")
        .ok_or_else(|| anyhow!("snitch-ebpf package not found"))?;
    let cargo_metadata::Package {
        name,
        manifest_path,
        ..
    } = ebpf_package;
    let ebpf_package = aya_build::Package {
        name: name.as_str(),
        root_dir: manifest_path
            .parent()
            .ok_or_else(|| anyhow!("no parent for {manifest_path}"))?
            .as_str(),
        ..Default::default()
    };
    aya_build::build_ebpf([ebpf_package], Toolchain::default())
}

fn ensure_frontend_bundle() -> anyhow::Result<()> {
    for path in [
        "../snitch-viewer/Cargo.toml",
        "../snitch-viewer/Dioxus.toml",
        "../snitch-viewer/tailwind.css",
        "../snitch-viewer/src",
        "../snitch-viewer/assets",
    ] {
        println!("cargo:rerun-if-changed={path}");
    }
    println!("cargo:rerun-if-env-changed=SNITCH_SKIP_FRONTEND_BUNDLE");
    println!("cargo:rerun-if-env-changed=SNITCH_FORCE_FRONTEND_BUNDLE");
    println!("cargo:rerun-if-env-changed=DX_BIN");

    if std::env::var("SNITCH_SKIP_FRONTEND_BUNDLE").as_deref() == Ok("1") {
        return Ok(());
    }

    let manifest_dir = PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR")
            .context("CARGO_MANIFEST_DIR is missing for snitch build script")?,
    );
    let workspace_root = manifest_dir
        .parent()
        .ok_or_else(|| anyhow!("snitch crate has no workspace root parent"))?;
    let index_html = workspace_root
        .join("target")
        .join("dx")
        .join("snitch-viewer")
        .join("release")
        .join("web")
        .join("public")
        .join("index.html");

    let force_bundle = std::env::var("SNITCH_FORCE_FRONTEND_BUNDLE").as_deref() == Ok("1");
    if !force_bundle && index_html.is_file() {
        return Ok(());
    }

    let dx_bin = std::env::var_os("DX_BIN").unwrap_or_else(|| OsString::from("dx"));
    let status = Command::new(&dx_bin)
        .current_dir(workspace_root)
        .args([
            "bundle",
            "--release",
            "--platform",
            "web",
            "-p",
            "snitch-viewer",
        ])
        .status()
        .with_context(|| {
            format!(
                "failed to run {:?} bundle --release --platform web -p snitch-viewer",
                dx_bin
            )
        })?;

    if !status.success() {
        return Err(anyhow!(
            "frontend bundle command failed with status {status}. \
             Install dioxus-cli + wasm toolchain, or run \
             `dx bundle --release --platform web -p snitch-viewer` manually."
        ));
    }

    if !index_html.is_file() {
        return Err(anyhow!(
            "frontend bundle completed but missing {}",
            index_html.display()
        ));
    }

    Ok(())
}
