use super::*;

// Statx has private reserved fields. Obtain a value from a test-owned file,
// then inject every relevant field; no host evidence or privileged mounts.
fn value() -> Snapshot {
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target");
    let file = tempfile::tempfile_in(base).unwrap();
    let mut stat = fs::statx(&file, "", AtFlags::EMPTY_PATH, REQUIRED).unwrap();
    stat.stx_mask = REQUIRED.bits();
    stat.stx_attributes_mask = StatxAttributes::AUTOMOUNT | StatxAttributes::MOUNT_ROOT;
    stat.stx_attributes = StatxAttributes::empty();
    stat.stx_nlink = 1;
    stat.stx_mode = 0o100600;
    stat.stx_uid = 1000;
    stat.stx_gid = 1000;
    stat.stx_mnt_id = 10;
    snapshot(stat).unwrap()
}

#[test]
fn unsupported_filesystems_and_missing_confinement_metadata_fail_closed() {
    for kind in [0xef53, 0x58465342, 0x9123683e] {
        assert_eq!(local_kind(kind), Ok(()));
    }
    // NFS, CIFS, FUSE, autofs, overlayfs, tmpfs, procfs, sysfs, unknown.
    for kind in [
        0x6969, 0xff534d42, 0x65735546, 0x187, 0x794c7630, 0x01021994, 0x9fa0, 0x62656572, 0,
    ] {
        assert_eq!(local_kind(kind), Err(Code::Unsupported));
    }
    let original = value().stat;
    for field in REQUIRED.iter() {
        let mut stat = original;
        stat.stx_mask &= !field.bits();
        assert!(
            matches!(snapshot(stat), Err(Code::Unsupported)),
            "{field:?}"
        );
    }
    for attribute in [StatxAttributes::AUTOMOUNT, StatxAttributes::MOUNT_ROOT] {
        let mut stat = original;
        stat.stx_attributes_mask.remove(attribute);
        assert!(matches!(snapshot(stat), Err(Code::Unsupported)));
    }
    let mut stat = original;
    stat.stx_attributes.insert(StatxAttributes::AUTOMOUNT);
    assert!(matches!(snapshot(stat), Err(Code::Unsupported)));
}

#[test]
fn mount_identity_link_count_types_and_excluded_inodes_are_independent_guards() {
    let original = value();
    let no_exclusions = Exclusions::default();
    assert_eq!(regular(&original, 10, &no_exclusions), Ok(()));
    let mut changed = original;
    changed.stat.stx_mnt_id = 11; // Same device and inode: a bind mount still fails.
    assert_eq!(
        regular(&changed, 10, &no_exclusions),
        Err(Code::AliasDenied)
    );
    for (links, reason) in [(0, Code::SourceDisappeared), (2, Code::AliasDenied)] {
        changed = original;
        changed.stat.stx_nlink = links;
        assert_eq!(regular(&changed, 10, &no_exclusions), Err(reason));
    }
    for mode in [0o010600, 0o020600, 0o040700, 0o060600, 0o140600] {
        changed = original;
        changed.stat.stx_mode = mode;
        assert_eq!(
            regular(&changed, 10, &no_exclusions),
            Err(Code::Unsupported)
        );
    }
    changed.stat.stx_mode = 0o120777;
    assert_eq!(
        regular(&changed, 10, &no_exclusions),
        Err(Code::AliasDenied)
    );
    let excluded = Exclusions::new(&[original.id]).unwrap();
    assert_eq!(regular(&original, 10, &excluded), Err(Code::AliasDenied));
    assert!(Exclusions::new(&[original.id; 32]).is_ok());
    assert!(matches!(
        Exclusions::new(&[original.id; 33]),
        Err(Code::ResourceLimit)
    ));
}

#[test]
fn directories_require_trusted_ownership_modes_and_a_scoped_non_mount_root() {
    let mut dir = value();
    assert_eq!(directory(&dir, 1000, true), Err(Code::AliasDenied));
    dir.stat.stx_mode = 0o040700;
    assert_eq!(directory(&dir, 1000, true), Ok(()));
    dir.stat.stx_uid = 0;
    assert_eq!(directory(&dir, 1000, false), Ok(()));
    dir.stat.stx_uid = 1001;
    assert_eq!(directory(&dir, 1000, true), Err(Code::PermissionDenied));
    dir.stat.stx_uid = 1000;
    for mode in [0o040720, 0o040702, 0o041777] {
        dir.stat.stx_mode = mode;
        assert_eq!(directory(&dir, 1000, true), Err(Code::PermissionDenied));
    }
    dir.stat.stx_mode = 0o040700;
    dir.stat.stx_nlink = 0;
    assert_eq!(directory(&dir, 1000, true), Err(Code::SourceDisappeared));
    dir.stat.stx_nlink = 2;
    dir.stat.stx_attributes.insert(StatxAttributes::MOUNT_ROOT);
    assert_eq!(directory(&dir, 1000, false), Ok(()));
    assert_eq!(directory(&dir, 1000, true), Err(Code::ScopeDenied));
}

#[test]
fn mutation_checks_cover_all_identity_and_content_fields_but_not_incidental_atime() {
    let original = value();
    assert_eq!(unchanged(&original, &original), Ok(()));
    let changes: [fn(&mut Snapshot); 12] = [
        |v| v.id.device += 1,
        |v| v.id.inode += 1,
        |v| v.stat.stx_mnt_id += 1,
        |v| v.stat.stx_size += 1,
        |v| v.stat.stx_mode ^= 0o020,
        |v| v.stat.stx_nlink += 1,
        |v| v.stat.stx_uid += 1,
        |v| v.stat.stx_gid += 1,
        |v| v.stat.stx_mtime.tv_sec += 1,
        |v| v.stat.stx_mtime.tv_nsec ^= 1,
        |v| v.stat.stx_ctime.tv_sec += 1,
        |v| v.stat.stx_ctime.tv_nsec ^= 1,
    ];
    for change in changes {
        let mut changed = original;
        change(&mut changed);
        assert_eq!(unchanged(&original, &changed), Err(Code::SourceChanged));
    }
    let mut changed = original;
    changed.stat.stx_atime.tv_sec += 1;
    assert_eq!(unchanged(&original, &changed), Ok(()));
}
