fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    // Windows reserves 1 MiB for the main thread, where Linux and macOS give
    // 8 MiB. clap's derive builds every `engine daemon` flag in one function,
    // and without optimization that frame alone is close to 1 MiB, so debug
    // builds overflowed on Windows before parsing the command line. Reserve
    // the same 8 MiB there.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        match std::env::var("CARGO_CFG_TARGET_ENV").as_deref() {
            Ok("msvc") => println!("cargo:rustc-link-arg-bin=rsigma=/STACK:8388608"),
            Ok("gnu") => println!("cargo:rustc-link-arg-bin=rsigma=-Wl,--stack,8388608"),
            _ => {}
        }
    }
}
