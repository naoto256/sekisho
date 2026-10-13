use std::collections::BTreeSet;
use std::path::Path;

fn rust_files(directory: &Path, files: &mut Vec<std::path::PathBuf>) {
    if !directory.exists() {
        return;
    }
    for entry in std::fs::read_dir(directory).unwrap() {
        let entry = entry.unwrap();
        let kind = entry.file_type().unwrap();
        let path = entry.path();
        if kind.is_dir() {
            rust_files(&path, files);
        } else if kind.is_file() && path.extension().is_some_and(|ext| ext == "rs") {
            files.push(path);
        }
    }
}

// Flags calls to tracing's subscriber-replacement functions in the other
// workspace crates, so that tests call the wrappers in `lib.rs` instead.
//
// Scope: the `.rs` files under `crates/<crate>/src` and `crates/<crate>/tests`,
// except this crate and the files listed in `subscriber-exclusions.txt`.
// Rule: one of the four names below, not preceded by an identifier character,
// followed on the same line by `(`, and not written as
// `sekisho_test_support::<name>(`. A wrapper call therefore has to spell the
// crate path at the call site. Comments and string literals are not skipped.
//
// Literal source checks are supplementary: aliases, macro-generated calls and
// entry points outside the four names, such as `.init()`, evade them. The
// wrappers check at runtime, but only the calls that go through them.
#[test]
fn no_raw_subscriber_entry_points() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let exclusions: BTreeSet<_> = include_str!("../subscriber-exclusions.txt")
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            let (file, reason) = line.split_once('\t').expect("exclusion needs a reason");
            assert!(!file.is_empty() && !reason.trim().is_empty());
            file
        })
        .collect();
    let mut files = Vec::new();
    for entry in std::fs::read_dir(root.join("crates")).unwrap() {
        let entry = entry.unwrap();
        if !entry.file_type().unwrap().is_dir() || entry.file_name() == "sekisho-test-support" {
            continue;
        }
        for directory in ["src", "tests"] {
            rust_files(&entry.path().join(directory), &mut files);
        }
    }
    files.sort();
    let mut violations = Vec::new();
    for file in files {
        let relative = file.strip_prefix(root).unwrap().to_str().unwrap();
        if exclusions.contains(relative) {
            continue;
        }
        let source = std::fs::read_to_string(&file).unwrap();
        for (line_number, line) in source.lines().enumerate() {
            for name in [
                "set_default",
                "with_default",
                "with_subscriber",
                "set_global_default",
            ] {
                for (offset, _) in line.match_indices(name) {
                    let prefix = &line[..offset];
                    let suffix = &line[offset + name.len()..];
                    let boundary = !prefix.ends_with(|c: char| c.is_alphanumeric() || c == '_');
                    if boundary
                        && suffix.trim_start().starts_with('(')
                        && !prefix.ends_with("sekisho_test_support::")
                    {
                        violations.push(format!("{relative}:{}: {name}", line_number + 1));
                    }
                }
            }
        }
    }
    assert!(
        violations.is_empty(),
        "raw subscriber entry points:\n{}",
        violations.join("\n")
    );
}
