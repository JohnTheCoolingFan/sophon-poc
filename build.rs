fn main() {
    protobuf_codegen::Codegen::new()
        .cargo_out_dir("protos")
        .include("src")
        .input("src/protos/SophonManifest.proto")
        .input("src/protos/SophonPatch.proto")
        .run_from_script();
}
