//! Test-only process isolation for tracing capture tests on Unix.
//!
//! `tracing` stores one cached `Interest` per callsite for the whole process,
//! combined from the subscribers active when it is computed. A subscriber that
//! a test installs for its own thread therefore shares that cache with the
//! other tests in the same binary. A test that replaces the subscriber runs
//! here in a child process that executes no other test.
//!
//! # Contract
//!
//! - Call [`run_in_child`] as the first statement of the test, passing the
//!   test's own libtest path (for example `audit::tests::name`), and return
//!   when it returns `true`. Statements before the call run in both processes.
//! - Replace the subscriber through [`set_default`], [`with_default`] or
//!   [`with_subscriber`]. Each panics unless `run_in_child` has returned
//!   `false` in this process.
//! - The `SEKISHO_ISOLATED_TEST` environment variable is reserved. The parent
//!   sets it to `<parent pid>:<test path>` for the child, and a process that
//!   has it set is treated as that child and panics if either part differs.
//! - The parent accepts the child when it exits successfully and its stdout
//!   has both the exact line `test <path> ... ok` and a line starting with
//!   `test result: ok. 1 passed; 0 failed; 0 ignored;`.
//!
//! The child uses libtest's pretty output. This API is not for ignored tests,
//! `#[should_panic]` tests, or doctests, and places no deadline on the child.

#![cfg(unix)]

use std::future::Future;
use std::process::Command;
use std::sync::OnceLock;
use tracing::Dispatch;
use tracing::instrument::WithSubscriber;

const MARKER: &str = "SEKISHO_ISOLATED_TEST";
static CHILD_TEST: OnceLock<String> = OnceLock::new();

fn validate_marker(test_path: &str) {
    let marker = std::env::var(MARKER).expect("invalid isolated test marker");
    let (pid, path) = marker
        .split_once(':')
        .expect("invalid isolated test marker");
    let pid: u32 = pid.parse().expect("invalid isolated test marker");
    assert_eq!(
        pid,
        std::os::unix::process::parent_id(),
        "wrong isolated test parent pid"
    );
    assert_eq!(path, test_path, "wrong isolated test path");
}

fn require_child() {
    let test_path = CHILD_TEST
        .get()
        .expect("subscriber replacement requires run_in_child in an isolated test");
    validate_marker(test_path);
}

fn child_passed(success: bool, stdout: &str, test_path: &str) -> bool {
    let named_result = format!("test {test_path} ... ok");
    success
        && stdout.lines().any(|line| line == named_result)
        && stdout
            .lines()
            .any(|line| line.starts_with("test result: ok. 1 passed; 0 failed; 0 ignored;"))
}

/// Run exactly this test in a child and return `true` in the parent on success.
/// The matching child returns `false`, so the caller can execute its test body.
/// The parent panics with the child's exit status, stdout and stderr when the
/// child is not accepted.
pub fn run_in_child(test_path: &str) -> bool {
    if std::env::var_os(MARKER).is_some() {
        validate_marker(test_path);
        assert_eq!(CHILD_TEST.get_or_init(|| test_path.into()), test_path);
        return false;
    }

    let output = Command::new(std::env::current_exe().expect("locate the test binary"))
        .args([
            test_path,
            "--exact",
            "--nocapture",
            "--test-threads=1",
            "--format=pretty",
            "--color=never",
        ])
        .env(MARKER, format!("{}:{test_path}", std::process::id()))
        .output()
        .expect("start the isolated test");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        child_passed(output.status.success(), &stdout, test_path),
        "isolated test {test_path} failed ({status})\nstdout:\n{stdout}\nstderr:\n{stderr}",
        status = output.status
    );
    true
}

/// Install a subscriber only after this process has entered its isolated test.
pub fn set_default<S: Into<Dispatch>>(subscriber: S) -> tracing::dispatcher::DefaultGuard {
    require_child();
    tracing::dispatcher::set_default(&subscriber.into())
}

/// Run a closure with a subscriber inside an isolated test process.
pub fn with_default<S, F, R>(subscriber: S, f: F) -> R
where
    S: Into<Dispatch>,
    F: FnOnce() -> R,
{
    require_child();
    tracing::dispatcher::with_default(&subscriber.into(), f)
}

/// Attach a subscriber to a future inside an isolated test process.
pub fn with_subscriber<F, S>(future: F, subscriber: S) -> impl Future<Output = F::Output>
where
    F: Future,
    S: Into<Dispatch>,
{
    require_child();
    future.with_subscriber(subscriber)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use tracing::subscriber::NoSubscriber;

    const MARKER: &str = "SEKISHO_ISOLATED_TEST";

    const GOOD_OUTPUT: &str = "running 1 test\ntest tests::example ... ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n";

    #[test]
    fn child_result_accepts_exact_single_test_success() {
        assert!(child_passed(true, GOOD_OUTPUT, "tests::example"));
    }

    #[test]
    fn child_result_rejects_two_passed() {
        let output = GOOD_OUTPUT.replace("1 passed", "2 passed");
        assert!(!child_passed(true, &output, "tests::example"));
    }

    #[test]
    fn child_result_rejects_missing_named_line() {
        let output = GOOD_OUTPUT.replace("test tests::example ... ok\n", "");
        assert!(!child_passed(true, &output, "tests::example"));
    }

    #[test]
    fn child_result_rejects_partial_named_line() {
        let output = GOOD_OUTPUT.replace(
            "test tests::example ... ok",
            "xxx test tests::example ... ok yyy",
        );
        assert!(!child_passed(true, &output, "tests::example"));
    }

    #[test]
    fn child_result_rejects_failed_exit() {
        assert!(!child_passed(false, GOOD_OUTPUT, "tests::example"));
    }

    #[test]
    fn child_result_rejects_ignored_test() {
        let output = GOOD_OUTPUT.replace("0 ignored", "1 ignored");
        assert!(!child_passed(true, &output, "tests::example"));
    }

    #[test]
    fn parent_reruns_the_named_test_once() {
        const PATH: &str = "tests::parent_reruns_the_named_test_once";
        if run_in_child(PATH) {
            return;
        }
        assert_eq!(
            std::env::var(MARKER).unwrap(),
            format!("{}:{PATH}", std::os::unix::process::parent_id())
        );
        assert!(
            !run_in_child(PATH),
            "the child must not launch another child"
        );
    }

    #[test]
    fn a_child_failure_fails_the_parent() {
        const PATH: &str = "tests::a_child_failure_fails_the_parent";
        if std::env::var_os(MARKER).is_some() {
            assert!(!run_in_child(PATH));
            panic!("intentional child failure");
        }
        let failure = std::panic::catch_unwind(|| run_in_child(PATH)).unwrap_err();
        let message = panic_message(failure);
        assert!(message.contains("intentional child failure"), "{message}");
        assert!(message.contains("stdout:"), "{message}");
        assert!(message.contains("stderr:"), "{message}");
    }

    #[test]
    fn a_missing_test_fails_the_parent() {
        let failure = std::panic::catch_unwind(|| run_in_child("tests::this_test_does_not_exist"))
            .unwrap_err();
        let message = panic_message(failure);
        assert!(
            message.contains("0 passed; 0 failed; 0 ignored;"),
            "{message}"
        );
    }

    fn assert_marker_rejected(path: &str, marker: String, expected: &str) {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                path,
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "--format=pretty",
                "--color=never",
            ])
            .env(MARKER, marker)
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !output.status.success(),
            "child accepted a mismatched marker"
        );
        assert!(stderr.contains(expected), "{stderr}");
    }

    #[test]
    fn a_wrong_marker_path_is_rejected() {
        const PATH: &str = "tests::a_wrong_marker_path_is_rejected";
        if std::env::var_os(MARKER).is_some() {
            run_in_child(PATH);
            panic!("wrong path was accepted");
        }
        assert_marker_rejected(
            PATH,
            format!("{}:tests::another_test", std::process::id()),
            "wrong isolated test path",
        );
    }

    #[test]
    fn a_wrong_parent_pid_is_rejected() {
        const PATH: &str = "tests::a_wrong_parent_pid_is_rejected";
        if std::env::var_os(MARKER).is_some() {
            run_in_child(PATH);
            panic!("wrong parent was accepted");
        }
        assert_marker_rejected(
            PATH,
            format!("{}:{PATH}", std::process::id().wrapping_add(1)),
            "wrong isolated test parent pid",
        );
    }

    #[test]
    fn a_malformed_marker_is_rejected() {
        const PATH: &str = "tests::a_malformed_marker_is_rejected";
        if std::env::var_os(MARKER).is_some() {
            run_in_child(PATH);
            panic!("malformed marker was accepted");
        }
        assert_marker_rejected(PATH, "not-a-marker".into(), "invalid isolated test marker");
    }

    #[test]
    fn subscriber_entry_points_reject_the_parent() {
        assert!(std::env::var_os(MARKER).is_none());
        assert!(std::panic::catch_unwind(|| set_default(NoSubscriber::default())).is_err());
        assert!(std::panic::catch_unwind(|| with_default(NoSubscriber::default(), || 7)).is_err());
        assert!(
            std::panic::catch_unwind(|| {
                with_subscriber(std::future::ready(7), NoSubscriber::default())
            })
            .is_err()
        );
    }

    #[test]
    fn subscriber_entry_points_accept_the_child() {
        const PATH: &str = "tests::subscriber_entry_points_accept_the_child";
        if run_in_child(PATH) {
            return;
        }
        let guard = set_default(NoSubscriber::default());
        drop(guard);
        assert_eq!(with_default(NoSubscriber::default(), || 7), 7);
        let future = with_subscriber(std::future::ready(11), NoSubscriber::default());
        let mut future = std::pin::pin!(future);
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        assert_eq!(
            future.as_mut().poll(&mut context),
            std::task::Poll::Ready(11)
        );
    }

    fn panic_message(panic: Box<dyn std::any::Any + Send>) -> String {
        if let Some(message) = panic.downcast_ref::<String>() {
            message.clone()
        } else if let Some(message) = panic.downcast_ref::<&str>() {
            (*message).into()
        } else {
            panic!("unexpected panic payload");
        }
    }
}
