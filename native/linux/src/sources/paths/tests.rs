use super::*;

#[test]
fn roots_reject_broad_kernel_and_malformed_paths_without_native_io() {
    for root in [
        "",
        "/",
        "relative",
        "/proc",
        "/proc/1",
        "/sys",
        "/sys/kernel",
        "/dev",
        "/dev/null",
        "/a/../b",
        "/a/./b",
        "/a//b",
        "/a/",
        "/nul\0",
    ] {
        assert_eq!(validate_root(root), Err(Code::ScopeDenied), "{root:?}");
    }
    for root in ["/explicit/case", "/proc-backup/case", "/測定/case"] {
        assert_eq!(validate_root(root), Ok(())); // Lexical only, no facility claim.
    }
    assert_eq!(validate_root(&format!("/{}", "a".repeat(4095))), Ok(()));
    assert_eq!(
        validate_root(&format!("/{}", "a".repeat(4096))),
        Err(Code::ScopeDenied)
    );
    assert_eq!(
        validate_root(&format!("/{}", vec!["a"; 256].join("/"))),
        Ok(())
    );
    assert_eq!(
        validate_root(&format!("/{}", vec!["a"; 257].join("/"))),
        Err(Code::ScopeDenied)
    );
}

#[test]
fn descendants_require_all_four_kernel_constraints_and_non_content_pins() {
    assert_eq!(
        CONFINED,
        ResolveFlags::BENEATH
            | ResolveFlags::NO_SYMLINKS
            | ResolveFlags::NO_MAGICLINKS
            | ResolveFlags::NO_XDEV
    );
    assert_eq!(PIN, OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW);
    assert!(!NO_LINKS.contains(ResolveFlags::NO_XDEV)); // Trusted root ancestry only.
}
