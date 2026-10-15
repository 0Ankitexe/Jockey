//! Pure construction checks. Do not open a bus, journal or evidence source here.
#[test]
fn no_default_journal_and_no_collection_at_startup() {
    assert!(jocky_native_linux::bootstrap().is_err());
    let manifest = include_str!("../Cargo.toml");
    assert!(manifest.contains("default = []"));
    assert!(manifest.contains("[target.'cfg(target_os = \"linux\")'.dependencies]"));
}

#[cfg(target_os = "linux")]
#[test]
fn dependencies_allow_inert_configuration_without_live_initialization() {
    let _builder = zbus::connection::Builder::address("unix:path=/run/dbus/system_bus_socket")
        .unwrap()
        .max_queued(8)
        .method_timeout(std::time::Duration::from_secs(2));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    assert_eq!(runtime.block_on(async { 2 + 2 }), 4);
}

#[cfg(all(target_os = "linux", feature = "journal"))]
#[test]
fn journal_file_api_is_available_but_not_called() {
    let _open_explicit = |files: &[&str]| {
        systemd::journal::OpenFilesOptions::default().open_files(files.iter().copied())
    };
}
