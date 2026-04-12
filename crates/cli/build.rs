//! Build script for the `cli` crate.
//!
//! Generates two rkyv-serialised baseline archives in `OUT_DIR`:
//!
//! - `slopsquat_corpus.rkyv` — a minimal seed corpus of known-malicious package
//!   names from the OSV MAL- advisory database.  Deployed when the OSV network
//!   endpoint is unreachable so that slopsquat detection never starts from zero.
//!
//! - `wisdom.rkyv` — an empty `WisdomSet` archive that deserialises correctly.
//!   Deployed as a no-op fallback so that `wisdom.rkyv` always exists and loads.
//!
//! Both archives are embedded into the binary via `include_bytes!` in `main.rs`.

fn main() {
    let out_dir =
        std::path::PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR must be set by cargo"));

    // -----------------------------------------------------------------------
    // Seed slopsquat corpus
    // -----------------------------------------------------------------------
    // A curated baseline of confirmed MAL-advisory package names spanning npm,
    // PyPI, and crates.io.  This is intentionally conservative — it covers
    // only packages with published OSV MAL- advisories at the time of writing.
    // The live `update-slopsquat` command replaces this with the full corpus.
    let seed_packages: Vec<String> = vec![
        // npm — confirmed MAL-advisories
        "event-stream".into(),
        "flatmap-stream".into(),
        "electron-native-notify".into(),
        "crossenv".into(),
        "cross-env.js".into(),
        "jquery.js".into(),
        "discordi.js".into(),
        "discord.js-selfbot".into(),
        "nodemon2".into(),
        "mongose".into(),
        "babelcli".into(),
        "eslint-config-eslint".into(),
        "lodash.utils".into(),
        "colors.js".into(),
        "faker.js".into(),
        "ua-parser-js".into(),
        "coa".into(),
        "rc".into(),
        "node-ipc".into(),
        "peacenotwar".into(),
        // PyPI — confirmed MAL-advisories
        "colourama".into(),
        "djago".into(),
        "python-sqlite".into(),
        "setup-tools".into(),
        "urlib3".into(),
        "request-oauthlib2".into(),
        "pytorch-tpu".into(),
        "torchvison".into(),
        "noblox.js-promise".into(),
        // crates.io — confirmed MAL-advisories
        "rustdecimal".into(),
        "deser-hjson".into(),
        "bikeshed".into(),
    ];

    let seed_corpus = common::wisdom::SlopsquatCorpus {
        package_names: seed_packages,
    };
    let corpus_bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&seed_corpus)
        .expect("build.rs: rkyv serialisation of seed corpus must not fail");
    std::fs::write(
        out_dir.join("slopsquat_corpus.rkyv"),
        corpus_bytes.as_slice(),
    )
    .expect("build.rs: writing embedded slopsquat_corpus.rkyv must not fail");

    // -----------------------------------------------------------------------
    // Empty wisdom baseline
    // -----------------------------------------------------------------------
    // A valid WisdomSet with no KEV rules.  Provides a deserialise-safe
    // fallback so wisdom.rkyv always exists on first boot.  No KEV coverage
    // until `janitor update-wisdom` is run.
    let empty_wisdom = common::wisdom::WisdomSet::default();
    let wisdom_bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&empty_wisdom)
        .expect("build.rs: rkyv serialisation of empty WisdomSet must not fail");
    std::fs::write(out_dir.join("wisdom.rkyv"), wisdom_bytes.as_slice())
        .expect("build.rs: writing embedded wisdom.rkyv must not fail");

    println!("cargo:rerun-if-changed=build.rs");
}
