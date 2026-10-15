#[path = "src/collection/schema/resources.rs"]
mod resources;
mod schema_build;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=schema_build.rs");
    println!("cargo:rerun-if-changed=src/collection/schema/resources.rs");
    let mut sources = Vec::new();
    for resource in &resources::SCHEMAS {
        println!("cargo:rerun-if-changed={}", resource.path);
        sources.push((resource.path, resource.contents));
    }
    schema_build::check(&sources).expect("embedded collection schema build guard failed");
}
