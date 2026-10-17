use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let proto_dir = manifest_dir.join("proto");

    // f1r3node client-only surface (we only talk to the server). Server
    // stubs would compile but we never serve these, so skip them.
    let node_proto_files = [
        "CasperMessage.proto",
        "DeployServiceCommon.proto",
        "DeployServiceV1.proto",
        "ProposeServiceCommon.proto",
        "ProposeServiceV1.proto",
        "RhoTypes.proto",
        "ServiceError.proto",
    ];
    let node_absolute: Vec<PathBuf> = node_proto_files.iter().map(|f| proto_dir.join(f)).collect();

    for f in &node_absolute {
        println!("cargo:rerun-if-changed={}", f.display());
    }
    println!(
        "cargo:rerun-if-changed={}",
        proto_dir.join("scalapb/scalapb.proto").display()
    );

    tonic_prost_build::configure()
        .build_client(true)
        .build_server(false)
        .btree_map(".")
        .bytes(".casper")
        .bytes(".routing")
        // Mirror f1r3node-rust's suppression — the generated service traits
        // use snake-case module names that clippy would otherwise flag.
        .client_mod_attribute(".", "#[allow(non_camel_case_types)]")
        .compile_protos(&node_absolute, std::slice::from_ref(&proto_dir))
        .expect("failed to compile f1r3node protobuf definitions");

    // Finder Sync extension service: the daemon SERVES this for the
    // macOS extension to call into. Also generate the client so e2e
    // tests can drive it without shelling out to grpcurl.
    let ext_proto = proto_dir.join("FinderSyncExtensionService.proto");
    println!("cargo:rerun-if-changed={}", ext_proto.display());

    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .client_mod_attribute(".generic", "#[allow(non_camel_case_types)]")
        .server_mod_attribute(".generic", "#[allow(non_camel_case_types)]")
        .compile_protos(
            std::slice::from_ref(&ext_proto),
            std::slice::from_ref(&proto_dir),
        )
        .expect("failed to compile FinderSyncExtensionService.proto");
}
