// Link against libfuse-t.
//
// On macOS, fuse-t ships `/usr/local/lib/libfuse-t.dylib` and
// `/usr/local/lib/pkgconfig/fuse-t.pc`. We prefer pkg-config so Linux /
// different prefixes keep working, falling back to a hard-coded `-L` on
// macOS if pkg-config isn't configured.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    if cfg!(not(target_os = "macos")) {
        // Not on macOS: assume Linux FUSE is used via a different code path
        // and this crate is a no-op. Downstream crates should #[cfg]-gate.
        return;
    }

    if let Err(e) = pkg_config::Config::new().probe("fuse-t") {
        eprintln!("pkg-config fuse-t failed: {e}; falling back to /usr/local/lib");
        println!("cargo:rustc-link-search=native=/usr/local/lib");
        println!("cargo:rustc-link-lib=fuse-t");
        // fuse-t's dylib has install_name @rpath/libfuse-t.dylib, so bake
        // an rpath into any downstream binary.
        println!("cargo:rustc-link-arg=-Wl,-rpath,/usr/local/lib");
    } else {
        // pkg-config emits -L and -l; we still need the rpath.
        println!("cargo:rustc-link-arg=-Wl,-rpath,/usr/local/lib");
    }
}
