//! # 1bm: single binary manager
//!
//! This is a CLI application. This documentation is for internal details.
//! The crate is named *onebm* because Cargo doesn't allow crate names starting with numbers.
//!
//! All the metadata, downloaded binaries, and 1bm itself, are stored under `~/.local/1bm`.
//! We intentionally don't use standard directories
//! because we want to make it convenient to manually inspect and change things.
//!
//! All downloaded binaries are under `~/.local/1bm/bin`.
//! The user is asked to add it to `PATH` to use them.
//!
//! Metadata are under `~/.local/1bm`. Specifically:
//!
//! - Installed binary list is at `~/.local/1bm/installed.json`. It's used to keep track of
//! information like version, dist file, and name of each binary.
//! - Dist files are at `~/.local/1bm/{FILE_HASH}.1bmdist`.
//! The hash is SHA-256 hex digest of the dist file and referenced in the installed binary list.
//!
//!

use {
	std::{
		fs,
		path::{Path, PathBuf},
	},
	// The user waits for downloads anyway.
	minisign_verify::{PublicKey, Signature},
	serde::{Serialize, Deserialize},
	bytes::Bytes,
	regex::Regex,
	sha2::{Sha256, Digest},
	semver::Version,
	home::home_dir,
	once_cell::sync::Lazy,
};

#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::unix::fs::PermissionsExt;

pub static R: Lazy<reqwest::blocking::Client> = Lazy::new(|| reqwest::blocking::ClientBuilder::new()
	.user_agent(concat!("1bm/", env!("CARGO_PKG_VERSION")))
	.gzip(true)
	.build()
	.unwrap()
);

pub static BASE_DIR: Lazy<PathBuf> = Lazy::new(|| {
	// We don't have a place to store binaries if there's no home directory.
	let mut path = home_dir().unwrap();
	path.push(".local");
	path.push("1bm");
	path
});

pub static BIN_DIR: Lazy<PathBuf> = Lazy::new(|| {
	let mut path = BASE_DIR.clone();
	path.push("bin");
	path
});

pub static IBL_PATH: Lazy<PathBuf> = Lazy::new(|| {
	let mut path = BASE_DIR.clone();
	path.push("installed.json");
	path
});

pub fn bin_path(name: &str) -> PathBuf {
	let mut path = BIN_DIR.clone();
	path.push(name);
	path
}

pub fn timestamp_now() -> u64 {
	std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap()
		.as_secs()
}

/// Corresponds to a dist file.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DistFile {
	pub binary_name: String,
	pub signing_key: String,
	pub download_url: String,
	pub download_type: String,

	pub github_asset_regex_linux: Option<String>,
	pub github_asset_regex_macos: Option<String>,
	pub github_asset_regex_windows: Option<String>,

}

/// Metadata about a binary. Corresponds to one entry in `installed.json`.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BinaryMeta {
	pub name: String,
	pub version: String,
	pub dist_hash: String,
	pub installed: u64,
	pub updated: u64,
	#[serde(skip_serializing)]
	pub distfile: Option<DistFile>,
}

pub fn install_binary(distfile: &DistFile, name: Option<&str>) -> TResult<BinaryMeta> {
	let dist_str = serde_json::to_string(distfile)?;
	let dist_hash = sha256(&dist_str);

	let ts_now = timestamp_now();

	let mut meta = BinaryMeta{
		name: name.unwrap_or(&distfile.binary_name).to_string(),
		version: "0.0.0".to_string(),
		dist_hash,
		distfile: Some(distfile.clone()),
		installed: ts_now,
		updated: ts_now,
	};
	let (_, version) = check_update(&meta)?;
	meta.version = version;

	update_binary(&meta)?;
	if let Some(name) = name {
		fs::rename(bin_path(&meta.name), bin_path(name))?;
	}

	let mut dist_path = BASE_DIR.clone();
	dist_path.push(format!("{}.1bmdist", &meta.dist_hash));
	fs::write(dist_path, dist_str)?;

	let mut binaries = read_binary_list()?;
	binaries.insert(0, meta.clone());
	binaries.sort_unstable_by(|a, b| a.name.cmp(&b.name));
	binaries.dedup_by(|a, b| a.name == b.name);
	write_binary_list(binaries)?;

	Ok(meta)
}

pub fn update_binary(meta: &BinaryMeta) -> TResult<()> {
	let distfile = meta.distfile.as_ref().unwrap();

	let (data, sig) = download(distfile)?;
	verify(&data, &distfile.signing_key, &sig)?;

	let path = bin_path(&meta.name);
	let temp_path = bin_path(&format!("{}.updated", &meta.name));
	fs::write(&temp_path, data)?;
	fs::rename(&temp_path, &path)?;

	#[cfg(any(target_os = "linux", target_os = "macos"))]
	fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?; // rwxr-xr-x

	let mut binaries = read_binary_list()?;
	for m in binaries.iter_mut() {
		if m.name == meta.name {
			m.updated = timestamp_now();
			m.version = meta.version.clone();
			break;
		}
	}
	write_binary_list(binaries)?;

	Ok(())
}

pub fn uninstall_binary(meta: &BinaryMeta) -> TResult<()> {
	let path = bin_path(&meta.name);
	fs::remove_file(path)?;

	let mut path = BASE_DIR.clone();
	path.push(format!("{}.1bmdist", meta.dist_hash));
	fs::remove_file(path)?;

	let mut binaries = read_binary_list()?;
	binaries.retain(|m| meta.name != m.name);
	write_binary_list(binaries)?;

	Ok(())
}

pub fn verify(data: &[u8], key: &str, sig: &str) -> TResult<()> {
	PublicKey::from_base64(key).map_err(|_| OnebmError::FailedVerification(format!("invalid key: {}", key)))?
		.verify(data, &Signature::decode(sig).map_err(|_| OnebmError::FailedVerification(format!("invalid signature: {}", sig)))?, false)
		.map_err(|_| OnebmError::FailedVerification("bad signature".to_string()))?;
	Ok(())
}

/// Check if a binary should be updated.
/// In addition to a bool, the new version is also returned.
///
pub fn check_update(meta: &BinaryMeta) -> TResult<(bool, String)> {
	let dist = meta.distfile.as_ref().unwrap();
	match dist.download_type.as_str() {
		"url" => check_update_url(meta),
		"ghr" => check_update_github_release(meta),
		dt => Err(OnebmError::UnsupportedDownloadType(dt.to_string(), dist.binary_name.to_owned())),
	}
}

/// Check update for direct URL downloads.
///
/// The "version" is either `ETag` or `Last-Modified`. `ETag` is preferred over `Last-Modified`.
/// If both are absent, an update is deemed always needed, and the time is used as the "version".
///
fn check_update_url(meta: &BinaryMeta) -> TResult<(bool, String)> {
	let resp = R.head(&meta.distfile.as_ref().unwrap().download_url).send()?;
	let headers = resp.headers();
	let tag = headers.get(reqwest::header::ETAG).map(|etag| format!("ETag:{}", etag.to_str().unwrap()))
		.or_else(|| headers.get(reqwest::header::LAST_MODIFIED).map(|lm| format!("LastMod:{}", lm.to_str().unwrap())));
	Ok(if let Some(tag) = tag {
		(tag != meta.version, tag)
	} else {
		(true, format!("Time:{}", timestamp_now()))
	})
}

fn check_update_github_release(meta: &BinaryMeta) -> TResult<(bool, String)> {
	let release = GitHubRelease::try_from(meta.distfile.as_ref().unwrap())?;
	let ver = release.tag_name.trim_start_matches(|c: char| !c.is_ascii_digit()).to_string();
	Ok((Version::parse(&ver).unwrap() > Version::parse(&meta.version).unwrap(), ver))
}

/// Download binary and signature.
pub fn download(dist: &DistFile) -> TResult<(Bytes, String)> {
	match dist.download_type.as_str() {
		"url" => Ok((
			R.get(&dist.download_url).send()?.bytes()?,
			R.get(format!("{}.minisig", &dist.download_url)).send()?.text()?,
		)),
		"ghr" => download_github_release(dist),
		dt => Err(OnebmError::UnsupportedDownloadType(dt.to_string(), dist.binary_name.to_owned())),
	}
}

#[derive(Deserialize, Debug)]
struct GitHubRelease {
	tag_name: String,
	assets: Vec<GitHubReleaseAsset>,
}

impl TryFrom<&DistFile> for GitHubRelease {
	type Error = OnebmError;
	fn try_from(dist: &DistFile) -> TResult<Self> {
		let release: Self = R.get(format!("https://api.github.com/repos/{}/releases/latest", dist.download_url)).send()?.json()?;
		Ok(release)
	}
}

#[derive(Deserialize, Debug)]
struct GitHubReleaseAsset {
	name: String,
	browser_download_url: String,
}

fn download_github_release(dist: &DistFile) -> TResult<(Bytes, String)> {
	let release = GitHubRelease::try_from(dist)?;

	#[cfg(target_os = "linux")]
	let asset_regex = dist.github_asset_regex_linux.as_ref();
	#[cfg(target_os = "macos")]
	let asset_regex = dist.github_asset_regex_macos.as_ref();
	#[cfg(target_os = "windows")]
	let asset_regex = dist.github_asset_regex_windows.as_ref();

	let asset_regex = asset_regex.ok_or_else(|| OnebmError::BadDistFile(dist.clone(), "empty GitHub release asset regex".to_string()))?;
	let asset_regex = Regex::new(asset_regex).map_err(|_| OnebmError::BadDistFile(dist.clone(), format!("invalid GitHub release asset regex: `{}`", asset_regex)))?;

	let mut sig = String::new();
	let mut data = Bytes::new();

	for asset in release.assets {
		if asset_regex.is_match(&asset.name) && !asset.name.ends_with(".minisig") {
			sig = R.get(format!("{}.minisig", &asset.browser_download_url)).send()?.text()?;
			data = R.get(&asset.browser_download_url).send()?.bytes()?;
			break;
		}
	}
	
	Ok((data, sig))
}

pub fn ensure_path() {
	if !BIN_DIR.exists() {
		fs::create_dir_all(&*BIN_DIR).unwrap();
	}
	if !BASE_DIR.exists() {
		fs::create_dir(&*BASE_DIR).unwrap();
	}
}

/// Read dist file from either local path or an URL.
pub fn read_distfile(path: &str) -> TResult<DistFile> {
	let local_path = Path::new(path);
	let raw = if local_path.exists() {
		String::from_utf8_lossy(&fs::read(&local_path)?).to_string()
	} else {
		R.get(path).send()?.text()?
	};
	let parsed: DistFile = serde_json::from_str(&raw)?;
	Ok(parsed)
}

pub fn read_distfile_for_binary(meta: &BinaryMeta) -> TResult<DistFile> {
	let mut path = BASE_DIR.clone();
	path.push(format!("{}.1bmdist", meta.dist_hash));
	read_distfile(path.to_str().unwrap())
}

pub fn read_binary_list() -> TResult<Vec<BinaryMeta>> {
	let mut list: Vec<BinaryMeta> = if IBL_PATH.exists() {
		serde_json::from_str(&String::from_utf8_lossy(&fs::read(&*IBL_PATH)?).to_string())?
	} else {
		Vec::new()
	};
	for meta in list.iter_mut() {
		meta.distfile = Some(read_distfile_for_binary(meta)?);
	}
	Ok(list)
}

pub fn write_binary_list(list: Vec<BinaryMeta>) -> TResult<()> {
	Ok(fs::write(&*IBL_PATH, serde_json::to_string(&list)?)?)
}

pub fn sha256<D: AsRef<[u8]>>(data: D) -> String {
	base16ct::lower::encode_string(&Sha256::digest(data))
}

pub type TResult<T> = Result<T, OnebmError>;

#[derive(thiserror::Error, Debug)]
pub enum OnebmError {
	#[error("unsupported download type `{0}` for {1}")]
	UnsupportedDownloadType(String, String),
	#[error("bad dist file: {0:?}, reason: {1}")]
	BadDistFile(DistFile, String),
	#[error("verification failed, reason: {0}")]
	FailedVerification(String),
	#[error(transparent)]
	BadJSON(#[from] serde_json::Error),
	#[error(transparent)]
	IO(#[from] std::io::Error),
	#[error(transparent)]
	Network(#[from] reqwest::Error),
}

