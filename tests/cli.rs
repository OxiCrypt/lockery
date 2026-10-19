//! End-to-end tests of the `lockery` binary: `init`, `list` and unlocking.
//!
//! Each test gets its own temporary data directory via `LOCKERY_DATA_DIR`,
//! and a config path that doesn't exist (so defaults apply). Stdin isn't a
//! terminal here, so the password prompts read one line each.

use std::path::Path;

use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin_cmd;
use tempfile::TempDir;

/// Strong enough that the "easy to guess" question isn't asked.
const PASSWORD: &str = "correct-horse-battery-staple-94!";

/// The cheapest Argon2 settings, so tests don't spend a second per vault.
const FAST_KDF: [&str; 6] = [
    "--memory-mib",
    "19",
    "--iterations",
    "1",
    "--parallelism",
    "1",
];

fn lockery(data: &TempDir) -> Command {
    let mut cmd = cargo_bin_cmd!("lockery");
    cmd.env("LOCKERY_DATA_DIR", data.path())
        .env("LOCKERY_CONFIG", data.path().join("no-config.toml"));
    cmd
}

fn stdout(cmd: &mut Command) -> String {
    let out = cmd.assert().success().get_output().stdout.clone();
    String::from_utf8(out).unwrap()
}

fn stderr_of_failure(cmd: &mut Command) -> String {
    let out = cmd.assert().failure().get_output().stderr.clone();
    String::from_utf8(out).unwrap()
}

fn init(data: &TempDir, name: Option<&str>) -> String {
    let mut cmd = lockery(data);
    cmd.arg("init").args(name).args(FAST_KDF);
    cmd.write_stdin(format!("{PASSWORD}\n{PASSWORD}\n"));
    stdout(&mut cmd)
}

#[test]
fn init_list_and_unlock_named_vaults() {
    let data = TempDir::new().unwrap();

    let out = init(&data, None);
    assert!(out.contains("Created vault 'default'"), "{out}");
    let out = init(&data, Some("work"));
    assert!(out.contains("Created vault 'work'"), "{out}");
    assert!(data.path().join("default.lockery").is_file());
    assert!(data.path().join("work.lockery").is_file());

    let out = stdout(lockery(&data).arg("list"));
    assert_eq!(out, "default  (primary)\nwork\n");

    // `lockery` opens the primary vault, `lockery work` the named one.
    let out = stdout(lockery(&data).write_stdin(format!("{PASSWORD}\n")));
    assert!(out.contains("Unlocked 'default': 0 entries."), "{out}");
    let out = stdout(
        lockery(&data)
            .arg("work")
            .write_stdin(format!("{PASSWORD}\n")),
    );
    assert!(out.contains("Unlocked 'work': 0 entries."), "{out}");
}

#[test]
fn init_respects_cipher_and_kdf_flags() {
    let data = TempDir::new().unwrap();
    let mut cmd = lockery(&data);
    cmd.args(["init", "aes", "--cipher", "aes256gcm"])
        .args(FAST_KDF);
    cmd.write_stdin(format!("{PASSWORD}\n{PASSWORD}\n"));
    let out = stdout(&mut cmd);
    assert!(
        out.contains("AES-256-GCM, Argon2id 19 MiB × 1 pass × 1 lane"),
        "{out}"
    );
}

#[test]
fn open_by_path() {
    let data = TempDir::new().unwrap();
    init(&data, Some("elsewhere"));
    let path = data.path().join("elsewhere.lockery");

    let other = TempDir::new().unwrap(); // a data dir without this vault
    let mut cmd = lockery(&other);
    cmd.arg("--path")
        .arg(&path)
        .write_stdin(format!("{PASSWORD}\n"));
    let out = stdout(&mut cmd);
    assert!(out.contains("0 entries"), "{out}");
}

#[test]
fn wrong_password_fails() {
    let data = TempDir::new().unwrap();
    init(&data, None);
    let err = stderr_of_failure(lockery(&data).write_stdin("not it\n"));
    assert!(err.contains("wrong password"), "{err}");
}

#[test]
fn init_refuses_existing_vault_and_mismatched_passwords() {
    let data = TempDir::new().unwrap();
    init(&data, None);

    let mut again = lockery(&data);
    again
        .arg("init")
        .args(FAST_KDF)
        .write_stdin(format!("{PASSWORD}\n{PASSWORD}\n"));
    assert!(stderr_of_failure(&mut again).contains("already exists"));

    let mut mismatch = lockery(&data);
    mismatch.args(["init", "other"]).args(FAST_KDF);
    mismatch.write_stdin(format!("{PASSWORD}\nsomething else\n"));
    assert!(stderr_of_failure(&mut mismatch).contains("don't match"));
    assert!(!data.path().join("other.lockery").exists());
}

#[test]
fn weak_password_needs_confirmation() {
    let data = TempDir::new().unwrap();

    let mut declined = lockery(&data);
    declined
        .args(["init", "weak"])
        .args(FAST_KDF)
        .write_stdin("password\npassword\nn\n");
    assert!(stderr_of_failure(&mut declined).contains("cancelled"));
    assert!(!data.path().join("weak.lockery").exists());

    let mut accepted = lockery(&data);
    accepted
        .args(["init", "weak"])
        .args(FAST_KDF)
        .write_stdin("password\npassword\ny\n");
    stdout(&mut accepted);
    assert!(data.path().join("weak.lockery").exists());
}

#[test]
fn invalid_and_missing_names_are_reported() {
    let data = TempDir::new().unwrap();
    let err = stderr_of_failure(lockery(&data).args(["init", "../escape"]).args(FAST_KDF));
    assert!(err.contains("invalid vault name"), "{err}");

    let err = stderr_of_failure(lockery(&data).arg("nope"));
    assert!(err.contains("lockery init nope"), "{err}");

    let out = stdout(lockery(&data).arg("list"));
    assert!(out.starts_with("No vaults"), "{out}");
}

#[test]
fn out_of_range_kdf_is_rejected() {
    let data = TempDir::new().unwrap();
    let err = stderr_of_failure(lockery(&data).args(["init", "--memory-mib", "1"]));
    assert!(err.contains("invalid Argon2 parameters"), "{err}");
    assert!(!Path::new(&data.path().join("default.lockery")).exists());
}
