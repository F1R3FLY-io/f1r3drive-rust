use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let proto_dir = manifest_dir.join("proto");

    let proto_files = [
        "CasperMessage.proto",
        "DeployServiceCommon.proto",
        "DeployServiceV1.proto",
        "ProposeServiceCommon.proto",
        "ProposeServiceV1.proto",
        "RhoTypes.proto",
        "ServiceError.proto",
    ];

    let absolute: Vec<PathBuf> = proto_files.iter().map(|f| proto_dir.join(f)).collect();

    for f in &absolute {
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
        .compile_protos(&absolute, &[proto_dir])
        .expect("failed to compile protobuf definitions");
}
