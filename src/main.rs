use std::{
    fs::File,
    io::{Read, Seek},
    os::unix::fs::FileExt,
    path::{Path, PathBuf},
    process::{Command, exit},
    str::from_utf8,
    sync::mpsc,
};

use proto_parsers::{
    SophonManifest::{SophonManifestAssetProperty, SophonManifestProto},
    SophonPatch::{
        SophonPatchAssetChunk, SophonPatchAssetProperty, SophonPatchProto, SophonUnusedAssetFile,
    },
};
use protobuf::Message;
use schemas::{
    ApiResponse, game_branches::GameBranches, sophon_diff::SophonDiffs,
    sophon_manifests::SophonManifests,
};
use xxhash_rust::xxh64::xxh64;

mod proto_parsers;
mod schemas;

const HOST: &str = concat!("https://sg-public-api.", "h", "oy", "over", "se", ".com");

const GAME_BRANCHES: &str = concat!(
    "https://sg-hyp-api.",
    "h",
    "oy",
    "over",
    "se",
    ".com/hyp/hyp-connect/api/getGameBranches?launcher_id=VYTpXlbWo8"
);

fn sophon_chunk_url(password: &str, package_id: &str) -> String {
    format!(
        "{}/downloader/sophon_chunk/api/getBuild?branch=main&password={password}&package_id={package_id}",
        HOST
    )
}

fn sophon_patch_url(password: &str, package_id: &str) -> String {
    format!(
        "{}/downloader/sophon_chunk/api/getPatchBuild?branch=main&password={password}&package_id={package_id}",
        HOST
    )
}

fn main() {
    //patch_test()
    download_test();
}

fn get_game_ver(path: impl AsRef<Path>) -> String {
    let bytes = std::fs::read(path.as_ref().join(".version")).unwrap();
    let major = bytes[0];
    let minor = bytes[1];
    let patch = bytes[2];
    format!("{major}.{minor}.{patch}")
}

fn patch_test() {
    let game_codename = "hk4e_global";
    let target_dir = "/hdd/jtcf/gayshit/Genshin Impact/";
    let from_ver = get_game_ver(target_dir);
    println!("Detected game version {from_ver}");
    println!("Start");
    let game_branches_sophon = minreq::get(GAME_BRANCHES).send().unwrap();
    let val: ApiResponse<GameBranches> = game_branches_sophon.json().unwrap();
    println!("GameBranches fetched and parsed");
    let game_info = val
        .data
        .game_branches
        .iter()
        .find(|gbi| gbi.game.biz == game_codename)
        .unwrap();
    let sophon_url = sophon_patch_url(&game_info.main.password, &game_info.main.package_id);
    let sophon_resp = minreq::post(&sophon_url).send().unwrap();
    let sophon_manifest_info: ApiResponse<SophonDiffs> = sophon_resp.json().unwrap();
    println!("SophonDiff fetched and parsed");

    let game_manifest = &sophon_manifest_info
        .data
        .manifests
        .iter()
        .find(|man| man.matching_field == "game")
        .expect("No game manifest?..");
    let manifest_id = &game_manifest.manifest.id;
    let manifest_url = format!(
        "{}{}/{manifest_id}",
        game_manifest.manifest_download.url_prefix, game_manifest.manifest_download.url_suffix
    );

    let manifest_req = minreq::get(&manifest_url).send().unwrap();
    println!("Status {}", manifest_req.status_code);
    let manifest_bytes = manifest_req.as_bytes();
    println!("Compressed size {}", manifest_bytes.len());
    std::fs::write(format!("{manifest_id}.zstd"), manifest_bytes).unwrap();
    let decompressed_manifest = zstd::decode_all(manifest_bytes).unwrap();
    println!("Decompressed size {}", decompressed_manifest.len());
    std::fs::write(format!("{manifest_id}.bin"), &decompressed_manifest).unwrap();

    println!("Parsing protobuf");

    let manifest_parsed = SophonPatchProto::parse_from_bytes(&decompressed_manifest).unwrap();
    println!("Protobuf parsed");

    //println!("{manifest_parsed:#?}");
    let manifest_text = format!("{manifest_parsed:#?}");
    std::fs::write("patch.txt", manifest_text).unwrap();
    println!("Manifest contents written to file patch.txt");

    let diff_base_url = format!(
        "{}{}",
        game_manifest.diff_download.url_prefix, game_manifest.diff_download.url_suffix
    );

    sophon_apply_patches(manifest_parsed, target_dir, &diff_base_url, &from_ver);
}

fn hdiffz_patch(
    target_file: impl AsRef<Path>,
    patch_file: impl AsRef<Path>,
    out_file: impl AsRef<Path>,
) {
    let patch_res = Command::new("./external/hpatchz/hpatchz")
        .args([target_file.as_ref(), patch_file.as_ref(), out_file.as_ref()])
        .output()
        .unwrap();
    if !patch_res.stderr.is_empty() {
        if let Ok(stderrout) = from_utf8(&patch_res.stderr) {
            eprintln!("{stderrout}")
        } else {
            println!("Not UTF-8 stderr")
        }
    }
}

fn sophon_apply_patches(
    patches_manifest: SophonPatchProto,
    target_dir: impl AsRef<Path>,
    diff_base_url: &str,
    installed_ver: &str,
) {
    let unused_assets_for_ver = patches_manifest
        .UnusedAssets
        .iter()
        .find(|(version, _unused_asset)| *version == installed_ver);
    if let Some((_unused_ver, unused_asset)) = unused_assets_for_ver {
        remove_unused_files(&unused_asset.Assets, &target_dir);
    }

    for patchinfo in &patches_manifest.PatchAssets {
        sophon_patch_file(patchinfo, &target_dir, diff_base_url, installed_ver);
        println!();
    }
}

fn check_file(file_path: impl AsRef<Path>, expected_size: u64, expected_md5: &str) {
    if std::fs::exists(&file_path).unwrap() {
        let mut file = File::open(&file_path).unwrap();
        let file_size = file.metadata().unwrap().len();
        assert!(file_size == expected_size);
        println!("Size matches");
        let mut buf = Vec::with_capacity(file_size as usize);
        file.read_to_end(&mut buf).unwrap();
        let md5_digest = md5::compute(&buf);
        let md5_hash = format!("{md5_digest:x}");
        assert!(expected_md5 == md5_hash);
        println!("MD5 matches");
    } else {
        println!("Doesn't exist, skipping check")
    }
}

fn sophon_patch_file(
    patch_info: &SophonPatchAssetProperty,
    target_dir: impl AsRef<Path>,
    diff_base_url: &str,
    installed_ver: &str,
) {
    println!("File {}", patch_info.AssetName);
    let target_file_path = target_dir.as_ref().join(&patch_info.AssetName);
    let assetinfo = patch_info
        .AssetInfos
        .iter()
        .find(|ainfo| ainfo.VersionTag == installed_ver);
    if let Some(asset_info) = assetinfo {
        let chunk = asset_info.Chunk.as_ref().unwrap();
        if chunk.OriginalFileName.is_empty() {
            println!("Copying new file `{}`", patch_info.AssetName);
            copy_over_file(
                target_file_path,
                chunk,
                diff_base_url,
                patch_info.AssetSize as u64,
                &patch_info.AssetHashMd5,
            )
        } else {
            let source_file_path = target_dir.as_ref().join(&chunk.OriginalFileName);
            if source_file_path == target_file_path {
                println!("Patching `{}`", target_file_path.display());
            } else {
                println!(
                    "Patching `{}` => `{}`",
                    source_file_path.display(),
                    target_file_path.display()
                )
            }
            actually_patch_file(
                diff_base_url,
                target_file_path,
                source_file_path,
                patch_info,
                chunk,
            )
        }
    } else {
        check_file(
            target_file_path,
            patch_info.AssetSize as u64,
            &patch_info.AssetHashMd5,
        )
    }
}

fn actually_patch_file(
    diff_base_url: &str,
    to: impl AsRef<Path>,
    from: impl AsRef<Path>,
    asset_info: &SophonPatchAssetProperty,
    patch_chunk: &SophonPatchAssetChunk,
) {
    check_file(
        &from,
        patch_chunk.OriginalFileLength as u64,
        &patch_chunk.OriginalFileMd5,
    );

    let patch_chunk_file = get_or_download_patch_chunk(
        diff_base_url,
        &patch_chunk.PatchName,
        patch_chunk.PatchSize as u64,
        &patch_chunk.PatchMd5,
    );
    let patch_data = extract_patch_chunk_region(
        patch_chunk_file,
        patch_chunk.PatchOffset as u64,
        patch_chunk.PatchLength as u64,
    );
    let patch_path_tmp = Path::new("/tmp/sophon-poc/").join(format!(
        "{}-{}.hdiff",
        patch_chunk.OriginalFileMd5, asset_info.AssetHashMd5
    ));
    std::fs::write(&patch_path_tmp, &patch_data).unwrap();
    let tmp_file_path =
        Path::new("/tmp/sophon-poc").join(format!("{}.tempfile", &asset_info.AssetHashMd5));
    println!(
        "Aplying patch `{}` on `{}` output to `{}`",
        patch_path_tmp.display(),
        from.as_ref().display(),
        tmp_file_path.display()
    );
    hdiffz_patch(&from, &patch_path_tmp, &tmp_file_path);

    // Delete original if patching is also a move
    if asset_info.AssetName != patch_chunk.OriginalFileName {
        std::fs::remove_file(from).unwrap();
    }

    println!("Checking post-patch");
    check_file(
        &tmp_file_path,
        asset_info.AssetSize as u64,
        &asset_info.AssetHashMd5,
    );

    std::fs::copy(&tmp_file_path, &to).unwrap();
    // tmp file was checked, doesn't need to be checked after copy
    std::fs::remove_file(&tmp_file_path).unwrap();
    std::fs::remove_file(&patch_path_tmp).unwrap();
}

fn copy_over_file(
    file_path: impl AsRef<Path>,
    chunk: &SophonPatchAssetChunk,
    diff_base_url: &str,
    expected_size: u64,
    expected_md5: &str,
) {
    let patch_chunk_path = get_or_download_patch_chunk(
        diff_base_url,
        &chunk.PatchName,
        chunk.PatchSize as u64,
        &chunk.PatchMd5,
    );
    let extracted_data = extract_patch_chunk_region(
        &patch_chunk_path,
        chunk.PatchOffset as u64,
        chunk.PatchLength as u64,
    );
    let tmp_file_path = Path::new("/tmp/sophon-poc/").join(format!("{}.tempfile", expected_md5));
    std::fs::write(&tmp_file_path, &extracted_data).unwrap();
    check_file(&tmp_file_path, expected_size, expected_md5);
    std::fs::copy(&tmp_file_path, &file_path).unwrap();
    std::fs::remove_file(tmp_file_path).unwrap();
}

fn extract_patch_chunk_region(patch_chunk: impl AsRef<Path>, offset: u64, length: u64) -> Vec<u8> {
    let mut buf = vec![0; length as usize];

    let file = File::open(patch_chunk).unwrap();
    file.read_exact_at(&mut buf, offset).unwrap();

    buf
}

fn get_or_download_patch_chunk(
    diff_base_url: &str,
    patch_id: &str,
    expected_size: u64,
    expected_md5: &str,
) -> PathBuf {
    let tmp_dir = "/tmp/sophon-poc/";
    let patch_chunk_path = Path::new(tmp_dir).join(format!("{patch_id}.pchunk"));
    if !std::fs::exists(&patch_chunk_path).unwrap() {
        println!("Downloading patch chunk {patch_id}");
        let patch_chunk_req = minreq::get(format!("{diff_base_url}/{patch_id}"))
            .send()
            .unwrap();
        let patch_chunk_bytes = patch_chunk_req.as_bytes();
        assert!(
            patch_chunk_bytes.len() == expected_size as usize,
            "size mismatch!"
        );
        assert!(
            bytes_check_md5(patch_chunk_bytes, expected_md5),
            "md5 mismatch!"
        );
        std::fs::write(&patch_chunk_path, patch_chunk_bytes).unwrap();
    }
    patch_chunk_path
}

fn bytes_check_md5(data: &[u8], expected: &str) -> bool {
    // this can be done in reverse, e.g. convert str to bytes and check against Digest
    let md5_digest = md5::compute(data);
    let md5_hash = format!("{md5_digest:x}");
    expected == md5_hash
}

fn remove_unused_files(unused_assets: &[SophonUnusedAssetFile], target_dir: impl AsRef<Path>) {
    for unused in unused_assets {
        println!("File `{}`", &unused.FileName);
        let file_path = target_dir.as_ref().join(&unused.FileName);
        if std::fs::exists(&file_path).unwrap() {
            let mut file = File::open(&file_path).unwrap();
            let file_size = file.metadata().unwrap().len();
            assert!(file_size == (unused.FileSize as u64));
            println!("Size matches");
            let mut buf = Vec::with_capacity(file_size as usize);
            file.read_to_end(&mut buf).unwrap();
            let md5_digest = md5::compute(&buf);
            let md5_hash = format!("{md5_digest:x}");
            assert!(unused.FileMd5 == md5_hash);
            println!("MD5 matches");
            drop(file);
            println!("Removing file");
            std::fs::remove_file(file_path).unwrap()
        } else {
            println!("Doesn't exist, skipping")
        }
        println!();
    }
}

// Todo:
// 2. download the full game using sophon
fn download_test() {
    let game_codename = "hk4e_global";
    let out_dir = "/hdd/jtcf/gayshit/gayshit downtest/";
    println!("Start");
    let game_branches_sophon = minreq::get(GAME_BRANCHES).send().unwrap();
    let val: ApiResponse<GameBranches> = game_branches_sophon.json().unwrap();
    println!("GameBranches fetched and parsed");
    let game_info = val
        .data
        .game_branches
        .iter()
        .find(|gbi| gbi.game.biz == game_codename)
        .unwrap();
    let sophon_url = sophon_chunk_url(&game_info.main.password, &game_info.main.package_id);

    let sophon_resp = minreq::get(&sophon_url).send().unwrap();
    let sophon_manifest_info: ApiResponse<SophonManifests> = sophon_resp.json().unwrap();
    println!("SophonManifests fetched and parsed");

    let game_manifest = &sophon_manifest_info
        .data
        .manifests
        .iter()
        .find(|man| man.matching_field == "game")
        .expect("No game manifest?..");
    let manifest_id = &game_manifest.manifest.id;
    let manifest_url = format!(
        "{}{}/{manifest_id}",
        game_manifest.manifest_download.url_prefix, game_manifest.manifest_download.url_suffix
    );

    let manifest_req = minreq::get(&manifest_url).send().unwrap();
    println!("Status {}", manifest_req.status_code);
    let manifest_bytes = manifest_req.as_bytes();
    println!("Compressed size {}", manifest_bytes.len());
    std::fs::write(format!("{manifest_id}.zstd"), manifest_bytes).unwrap();
    let decompressed_manifest = zstd::decode_all(manifest_bytes).unwrap();
    println!("Decompressed size {}", decompressed_manifest.len());
    std::fs::write(format!("{manifest_id}.bin"), &decompressed_manifest).unwrap();

    println!("Parsing protobuf");

    let manifest_parsed = SophonManifestProto::parse_from_bytes(&decompressed_manifest).unwrap();
    println!("Protobuf parsed");
    let mut sum: usize = 0;
    for asset in &manifest_parsed.Assets {
        assert!(asset.AssetSize > 0);
        sum += asset.AssetSize as usize
    }

    println!("Total size in bytes: {sum}");

    let chunk_base_url = format!(
        "{}{}",
        game_manifest.chunk_download.url_prefix, game_manifest.chunk_download.url_suffix
    );

    let manifest_dbg = format!("{manifest_parsed:#?}");
    std::fs::write("./game_manifest.txt", manifest_dbg).unwrap();
    println!("Written manifest to file");

    let mut downloaded = 0;
    let total_files = manifest_parsed.Assets.len();
    let reqw_client = reqwest::blocking::Client::new();
    for (i, asset) in manifest_parsed.Assets.iter().enumerate() {
        println!("File [{i}/{total_files}]");
        download_sophon_file(reqw_client.clone(), asset, &chunk_base_url, out_dir);
        downloaded += asset.AssetSize as u64;
        println!("Downloaded [{downloaded}/{sum}] (bytes)");
        println!();
    }
}

fn bytes_check_xxh(data: &[u8], expected: u64) -> bool {
    let hash = xxh64(data, 0);
    println!("XXH HASH GOT: {hash:x}");
    println!("XXH HASH EXP: {expected:x}");
    hash == expected
}

fn ensure_parent_exists(path: impl AsRef<Path>) {
    let parent_path = path.as_ref().parent();
    if let Some(path_to_check) = parent_path {
        if path_to_check != Path::new("") && !std::fs::exists(path_to_check).unwrap() {
            std::fs::create_dir_all(path_to_check).unwrap()
        }
    }
}

#[derive(Debug)]
struct FileChunk {
    offset: u64,
    data: Box<[u8]>,
}

fn download_sophon_file(
    reqw_client: reqwest::blocking::Client,
    asset_property: &SophonManifestAssetProperty,
    chunk_base_url: &str,
    out_dir: impl AsRef<Path>,
) {
    //let reqw_client = reqwest::blocking::Client::new();
    let out_path = out_dir.as_ref().join(&asset_property.AssetName);
    println!("Downloading {}", asset_property.AssetName);
    println!("Destination {}", out_path.display());
    ensure_parent_exists(&out_path);
    println!("Asset type {}", asset_property.AssetType);
    println!("Asset size {}", asset_property.AssetSize);
    println!("MD5 hash {}", asset_property.AssetHashMd5);
    let file_size = asset_property.AssetSize as u64;
    let (sender, receiver) = mpsc::channel::<FileChunk>();
    let writer_thread = std::thread::spawn(move || {
        let file = std::fs::File::create(&out_path).unwrap();
        file.set_len(file_size).unwrap();
        while let Ok(data_chunk) = receiver.recv() {
            file.write_all_at(&data_chunk.data, data_chunk.offset)
                .unwrap()
        }
    });
    let total_chunks = asset_property.AssetChunks.len();
    for (i, chunk) in asset_property.AssetChunks.iter().enumerate() {
        println!("Chunk [{i}/{total_chunks}]");
        println!("Chunk name {}", chunk.ChunkName);
        println!("Offset {}", chunk.ChunkOnFileOffset);
        println!("Downloading chunk");
        let url = format!("{}/{}", chunk_base_url, chunk.ChunkName);
        let chunk_req = reqw_client.get(&url).send().unwrap();
        let compressed_bytes = chunk_req.bytes().unwrap();
        /*
        assert!(
            bytes_check_xxh(compressed_bytes, chunk.ChunkCompressedHashXxh),
            "COMPRESSED CHUNK HASH MISMATCH"
        );
        */
        println!("Decompressing");
        let decompressed_bytes = zstd::decode_all(&*compressed_bytes).unwrap();
        assert!(
            bytes_check_md5(&decompressed_bytes, &chunk.ChunkDecompressedHashMd5),
            "CHUNK HASH MISMATCH"
        );
        println!("Writing to filesystem");
        sender
            .send(FileChunk {
                offset: chunk.ChunkOnFileOffset,
                data: decompressed_bytes.into_boxed_slice(),
            })
            .unwrap();
    }

    drop(sender);

    writer_thread.join().unwrap();
}
