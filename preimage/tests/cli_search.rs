use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

use tempfile::tempdir;

const NTLM_APPLE: &str = "5ebe7dfa074da8ee8aef1faa2bbde876";
const NTLM_MISS: &str = "00000000000000000000000000000000";
const CLOUDAP_HASHCAT: &str =
    "$MSONLINEACCOUNT$0$10000$91869d1d5d3a1df25dd3f0e57bbc226a43641bc03086dcb5b6672941fcabce01";

fn preimage() -> Command {
    Command::new(env!("CARGO_BIN_EXE_preimage"))
}

fn test_data(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("test_data")
        .join(name)
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn unified_search_reports_clear_ntlm_hit_and_miss() {
    let index = test_data("ntlm_sorted_reference.idx");
    let dictionary = test_data("words.txt");

    let hit = preimage()
        .args([
            "search",
            "-a",
            "ntlm",
            "-c",
            index.to_str().unwrap(),
            "-d",
            dictionary.to_str().unwrap(),
            NTLM_APPLE,
        ])
        .output()
        .expect("run NTLM hit");
    assert!(
        hit.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&hit.stderr)
    );
    assert!(stdout(&hit).contains("Password found: apple"));

    let miss = preimage()
        .args([
            "search",
            "-a",
            "ntlm",
            "-c",
            index.to_str().unwrap(),
            "-d",
            dictionary.to_str().unwrap(),
            NTLM_MISS,
        ])
        .output()
        .expect("run NTLM miss");
    assert!(
        miss.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&miss.stderr)
    );
    assert!(stdout(&miss).contains("Password not found"));
}

#[test]
fn cloudap_build_auto_selects_backend_and_unified_search_finds_hashcat() {
    let dir = tempdir().expect("tempdir");
    let cache = dir.path().join("words.cloudap33700.pim");
    let dictionary = test_data("cloudap33700_words.txt");

    let build = preimage()
        .args([
            "cloudap",
            "build",
            "-w",
            dictionary.to_str().unwrap(),
            "-o",
            cache.to_str().unwrap(),
        ])
        .output()
        .expect("build CloudAP cache");
    assert!(
        build.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&build.stderr)
    );

    let hit = preimage()
        .args([
            "search",
            "-c",
            cache.to_str().unwrap(),
            "-d",
            dictionary.to_str().unwrap(),
            CLOUDAP_HASHCAT,
        ])
        .output()
        .expect("search CloudAP cache");
    assert!(
        hit.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&hit.stderr)
    );
    assert!(stdout(&hit).contains("Password found: hashcat"));
}

#[test]
fn compact_cloudap_v2_builds_sidecar_and_searches() {
    let dir = tempdir().expect("tempdir");
    let cache = dir.path().join("words-v2.cloudap33700.pim");
    let dictionary = test_data("cloudap33700_words.txt");

    let build = preimage()
        .args([
            "cloudap",
            "build",
            "-w",
            dictionary.to_str().unwrap(),
            "-o",
            cache.to_str().unwrap(),
            "--compact-cache",
        ])
        .output()
        .expect("build compact CloudAP cache");
    assert!(
        build.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&build.stderr)
    );
    let mut sidecar = cache.as_os_str().to_os_string();
    sidecar.push(".ord");
    assert!(std::path::PathBuf::from(sidecar).exists());

    let hit = preimage()
        .args([
            "search",
            "-c",
            cache.to_str().unwrap(),
            "-d",
            dictionary.to_str().unwrap(),
            CLOUDAP_HASHCAT,
        ])
        .output()
        .expect("search compact CloudAP cache");
    assert!(
        hit.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&hit.stderr)
    );
    assert!(stdout(&hit).contains("Password found: hashcat"));
}

#[test]
fn default_search_config_supplies_algorithm_cache_and_dictionary() {
    let dir = tempdir().expect("tempdir");
    fs::copy(
        test_data("ntlm_sorted_reference.idx"),
        dir.path().join("ntlm.idx"),
    )
    .expect("copy index");
    fs::copy(test_data("words.txt"), dir.path().join("words.txt")).expect("copy dictionary");

    let config = dir.path().join("config.toml");
    fs::write(
        &config,
        "algorithm = \"ntlm\"\ncache = \"ntlm.idx\"\ndictionary = \"words.txt\"\n",
    )
    .expect("write config");

    let hit = preimage()
        .env("PREIMAGE_CONFIG", &config)
        .args(["search", NTLM_APPLE])
        .output()
        .expect("search with defaults");
    assert!(
        hit.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&hit.stderr)
    );
    assert!(stdout(&hit).contains("Password found: apple"));
}

#[test]
fn cloudap_build_help_has_no_backend_switch() {
    let help = preimage()
        .args(["cloudap", "build", "--help"])
        .output()
        .expect("cloudap build help");
    assert!(help.status.success());
    assert!(!stdout(&help).contains("--backend"));
}
