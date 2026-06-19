// src/main.rs
// rcrm - A simple file encryption/decryption tool
// Copyleft (©) 2024-2025 hibays

use std::cell::Cell;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use std::{fs, io};

use clap::{Parser, Subcommand};
use dialoguer::{Confirm, Password};
use indicatif::{ProgressBar, ProgressStyle};
use zeroize::Zeroizing;

use rcrm::serve::tls as tls_config;
use rcrm::serve::{AuthConfig, Server, ServerContext, generate_mount_names};
use rcrm::{Manager, SessionKey, is_supported_file, resolve_ne_path_from_dir_with_progress};

// =======================
// CLI Args
// =======================

#[derive(Parser)]
#[command(author, version, about)]
struct Args {
	#[command(subcommand)]
	command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
	/// Encrypt / decrypt files in place (default behaviour when no
	/// subcommand is given).
	Crypt {
		/// Directory to scan. Repeatable for multiple directories.
		/// Optional — defaults to "..". Can also be supplied as a bare
		/// positional argument: `rcrm /path` or `rcrm crypt /path`
		/// (single-directory only). Use repeated -d for multi-root.
		#[arg(short('d'), long)]
		dir: Vec<String>,
		/// Positional directory path (alternative to -d, single-dir only).
		path: Option<String>,
	},
	/// Start the projection FTP(S) server.
	Serve {
		/// Directory to serve. Repeatable for multiple roots.
		/// Defaults to "." if omitted. In multi-root mode each root
		/// appears as a virtual subdirectory named after its base.
		#[arg(short('d'), long)]
		dir: Vec<String>,
		/// Bind address (use 0.0.0.0 to expose to the network).
		#[arg(long, default_value = "127.0.0.1")]
		bind: String,
		/// Control connection port.
		#[arg(long)]
		port: Option<u16>,
		/// Implicit FTPS: the control connection is TLS-wrapped
		/// immediately on connect (no AUTH TLS negotiation). Data
		/// connections default to encrypted. Standard port is 990.
		/// Auto-generates a self-signed cert if --cert/--key are not
		/// supplied. Mutually exclusive with --ftpes.
		#[arg(long, conflicts_with = "ftpes")]
		ftps: bool,
		/// Explicit FTPS (FTPES): plain FTP that upgrades to TLS via
		/// AUTH TLS. Standard port is 21. Auto-generates a self-signed
		/// cert if --cert/--key are not supplied. Mutually exclusive
		/// with --ftps.
		#[arg(long, conflicts_with = "ftps")]
		ftpes: bool,
		/// WebDAV over plain HTTP. Standard port is 80. Mutually exclusive
		/// with --ftps, --ftpes, --https.
		#[arg(long, conflicts_with_all = ["ftps", "ftpes", "https"])]
		http: bool,
		/// WebDAV over HTTPS (implicit TLS). Standard port is 443.
		/// Auto-generates a self-signed cert if --cert/--key are not
		/// supplied. Mutually exclusive with --ftps, --ftpes, --http.
		#[arg(long, conflicts_with_all = ["ftps", "ftpes", "http"])]
		https: bool,
		/// Path to a PEM certificate chain (implies TLS).
		#[arg(long)]
		cert: Option<String>,
		/// Path to a PEM private key (implies TLS).
		#[arg(long)]
		key: Option<String>,
		/// Require this username for FTP login. When binding to anything
		/// other than loopback, a username is mandatory (otherwise the
		/// server refuses to start to prevent anonymous network exposure).
		/// On loopback, anonymous access is allowed when --user is absent.
		#[arg(long)]
		user: Option<String>,
		/// Allow anonymous access even when binding to a non-loopback
		/// address. By default the server refuses to start without --user
		/// in that case, to prevent accidental anonymous network exposure.
		/// Use --force to override this safety check (e.g. for trusted
		/// LANs behind a firewall).
		#[arg(long)]
		force: bool,
		/// Max simultaneous connections.
		#[arg(long, default_value_t = 16)]
		max_connections: usize,
	},
}

// =======================
// Helper: 获取密码
// =======================

fn get_user_password(prompt: &str, twofa: bool) -> io::Result<Zeroizing<String>> {
	let pwd = Password::new().with_prompt(prompt);
	if twofa {
		Ok(Zeroizing::new(
			pwd.with_confirmation("       CONFIRM", "Passwords do not match")
				.interact()?,
		))
	} else {
		Ok(Zeroizing::new(pwd.interact()?))
	}
}

// =======================
// String padding helper
// =======================

trait PadToWidth {
	fn pad_to_width(&self, width: usize) -> String;
}

impl PadToWidth for String {
	fn pad_to_width(&self, width: usize) -> String {
		let len = self.chars().count();
		let padding = " ".repeat(width.saturating_sub(len));
		format!("{}{}", self, padding)
	}
}

impl PadToWidth for &str {
	fn pad_to_width(&self, width: usize) -> String {
		self.to_string().pad_to_width(width)
	}
}

impl PadToWidth for std::borrow::Cow<'_, str> {
	fn pad_to_width(&self, width: usize) -> String {
		self.as_ref().pad_to_width(width)
	}
}

// =======================
// Main
// =======================

fn main() -> io::Result<()> {
	let args = preprocess_args();
	match args.command {
		Some(Command::Crypt { dir, path }) => {
			// Merge -d flags + positional path. Positional path only
			// works for single-directory mode.
			let mut dirs = dir;
			if let Some(p) = path {
				dirs.push(p);
			}
			if dirs.is_empty() {
				dirs.push("..".to_string());
			}
			run_crypt(dirs)
		}
		Some(Command::Serve {
			dir,
			bind,
			port,
			ftps,
			ftpes,
			http,
			https,
			cert,
			key,
			user,
			force,
			max_connections,
		}) => {
			let dirs: Vec<String> = if dir.is_empty() {
				vec![".".to_string()]
			} else {
				dir
			};
			run_serve(
				&dirs,
			&bind,
			port,
			ftps,
			ftpes,
			http,
			https,
			cert,
			key,
			user,
			force,
			max_connections,
		)
	},
	None => run_crypt(vec!["..".to_string()]),
	}
}

/// Pre-process `std::env::args` to make `crypt` the default subcommand and
/// allow a bare positional directory path (e.g. `rcrm /path/to/dir`) without
/// requiring `-d`. If the first argument is not `crypt`, `serve`, `help`, or
/// a known top-level flag (`--help`, `-h`, `--version`, `-V`), we inject
/// `crypt` as the subcommand so clap parses the rest as crypt args.
fn preprocess_args() -> Args {
	let raw: Vec<String> = std::env::args().collect();
	if raw.len() > 1 {
		let first = &raw[1];
		const TOP_LEVEL: &[&str] = &["--help", "-h", "--version", "-V"];
		if first == "crypt"
			|| first == "serve"
			|| first == "help"
			|| TOP_LEVEL.contains(&first.as_str())
		{
			Args::parse()
		} else {
			// Inject "crypt" so `rcrm /path` → `rcrm crypt /path`,
			// `rcrm -d /path` → `rcrm crypt -d /path`, etc.
			let mut modified = vec![raw[0].clone(), "crypt".to_string()];
			modified.extend(raw.iter().skip(1).cloned());
			Args::parse_from(modified)
		}
	} else {
		Args::parse()
	}
}

// =======================
// crypt subcommand (original in-place encrypt/decrypt behaviour)
// =======================

fn run_crypt(dirs: Vec<String>) -> io::Result<()> {
	// Canonicalize all directories and scan for files.
	let mut all_nor: Vec<PathBuf> = Vec::new();
	let mut all_enc: Vec<PathBuf> = Vec::new();

	for d in &dirs {
		let dir = PathBuf::from(d).canonicalize()?;
		println!("* Scanning: {}", dunce::canonicalize(&dir)?.display());

		let scan_pb = ProgressBar::new_spinner();
		scan_pb.set_style(
			ProgressStyle::default_spinner()
				.template(
					"{spinner:.green} Scanning... {pos} files scanned. {decimal_bytes_per_sec}",
				)
				.unwrap(),
		);
		scan_pb.enable_steady_tick(std::time::Duration::from_millis(100));

		let scanned_files = Cell::new(0);
		let (nor_videos, enc_videos) = resolve_ne_path_from_dir_with_progress(&dir, |count| {
			scan_pb.set_position(count as u64);
			scanned_files.set(count);
		});

		scan_pb.finish_with_message(format!(
			"Scan complete: {} files found",
			scanned_files.get()
		));

		all_nor.extend(nor_videos);
		all_enc.extend(enc_videos);
	}

	if all_nor.is_empty() && all_enc.is_empty() {
		eprintln!("No valid files found.");
		return Ok(());
	}

	let (is_encode, op_videos) = if !all_nor.is_empty() {
		if all_enc.is_empty() {
			(true, all_nor)
		} else {
			let encode = Confirm::new()
				.with_prompt("Want to encode?")
				.default(true)
				.interact()?;
			(encode, if encode { all_nor } else { all_enc })
		}
	} else {
		(false, all_enc)
	};

	println!(
		"{}",
		if is_encode {
			"<--- Encoding --->"
		} else {
			"<--- Decoding --->"
		}
	);

	let maxsize = op_videos
		.iter()
		.map(|p| p.file_name().unwrap().to_string_lossy().chars().count())
		.max()
		.unwrap_or(0);

	let password = get_user_password("INPUT PASSWORD", is_encode)?;
	let mut manager = Manager::new(
		true,
		true,
		2048,
		is_supported_file,
		6,
		Some(password.as_bytes()),
	);
	drop(password);

	let pb = ProgressBar::new(op_videos.len() as u64);
	pb.set_style(
		ProgressStyle::default_bar()
			.template("[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} {percent}% ({eta})")
			.unwrap(),
	);

	for file in &op_videos {
		let result = if is_encode {
			manager.encrypt_file(file)
		} else {
			manager.decrypt_file(file)
		};

		match result {
			Ok(new_name) => {
				let fname = file.file_name().unwrap().to_string_lossy();
				pb.println(format!(
					" 成功: \"{}\" -> \"{}\"",
					fname.pad_to_width(maxsize),
					new_name
				));
			}
			Err(e) => {
				let fname = file.file_name().unwrap().to_string_lossy();
				let fsize = file.metadata().map(|m| m.len()).unwrap_or(0);
				pb.println(format!(
					" 失败: \"{}\" ({}b)",
					fname.pad_to_width(maxsize),
					fsize
				));

				if e.kind() == io::ErrorKind::InvalidData && e.to_string() == "Uncorrected key!" {
					pb.println("\t↑ 密码错误!");

					let mut key_matched_in_prelist = false;
					for idx in manager.list_key_idxs().unwrap() {
						if idx == Manager::MAGIC_KEY_USING {
							continue;
						}
						pb.println(format!("\t↑ 尝试中: `{:}`", idx));
						manager.use_key(&idx);
						if let Ok(name) = manager.decrypt_file(file) {
							pb.println(format!("\t↑ 成功: -> \"{}\"", name));
							key_matched_in_prelist = true;
							break;
						} else {
							pb.println("\t↑ 密码错误!");
						}
					}
					if !key_matched_in_prelist {
						while let Ok(pwd) = pb.suspend(|| get_user_password("\t↑ 请重试-> ", false))
						{
							manager.use_added_key(pwd.as_bytes());
							drop(pwd);
							match manager.decrypt_file(file) {
								Ok(name) => {
									pb.println(format!("\t↑ 成功: -> \"{}\"", name));
									break;
								}
								Err(_) => {
									pb.println("\t↑ 密码错误!");
									if pb.suspend(|| {
										!Confirm::new()
											.with_prompt("\t↑ Proceed trying?")
											.interact()
											.unwrap_or(false)
									}) {
										pb.println("\t↑ Canceled!");
										break;
									}
								}
							}
						}
					}
				} else {
					pb.println(format!("\t↑ {} -> {}", e.kind(), e));
					if pb.suspend(|| {
						Confirm::new()
							.with_prompt("\t↑ Would you like to delete it?")
							.interact()
							.unwrap_or(false) && Confirm::new()
							.with_prompt("\t↑ Proceed?")
							.interact()
							.unwrap_or(false)
					}) {
						let _ = fs::remove_file(file);
						pb.println("\t↑ Deleted!");
					} else {
						pb.println("\t↑ Canceled!");
					}
				}
			}
		}

		pb.inc(1);
	}

	manager.drop_all_keys();
	pb.finish_with_message("ALL DONE");
	Ok(())
}

// =======================
// serve subcommand (projection FTP(S) server)
// =======================

#[allow(clippy::too_many_arguments)]
fn run_serve(
	dirs: &[String],
	bind: &str,
	port: Option<u16>,
	ftps: bool,
	ftpes: bool,
	http: bool,
	https: bool,
	cert: Option<String>,
	key: Option<String>,
	user: Option<String>,
	force: bool,
	max_connections: usize,
) -> io::Result<()> {
	// Canonicalize all root directories.
	let roots: Vec<PathBuf> = dirs
		.iter()
		.map(|d| {
			let p = PathBuf::from(d);
			dunce::canonicalize(&p).map_err(|e| {
				io::Error::new(
					io::ErrorKind::NotFound,
					format!("serve root '{}': {}", d, e),
				)
			})
		})
		.collect::<io::Result<_>>()?;

	for root in &roots {
		if !root.is_dir() {
			return Err(io::Error::new(
				io::ErrorKind::NotFound,
				format!("serve root '{}' is not a directory", root.display()),
			));
		}
	}

	// Generate mount names (disambiguated on collision).
	let mounts = generate_mount_names(&roots);
	eprintln!(
		"[serve] {} root(s): {}",
		mounts.len(),
		mounts
			.iter()
			.map(|m| format!("{} → {}", m.mount_name, m.disk_path.display()))
			.collect::<Vec<_>>()
			.join(", ")
	);

	// --- Resolve protocol + TLS mode ---
	// Priority: --ftps > --ftpes > --https > --http > --cert/--key (→ FTPES)
	// > plain FTP. clap's conflicts_with_all guarantees at most one of these
	// is set at a time, except --cert/--key which can accompany any.
	use rcrm::serve::Protocol;
	let (protocol, tls_enabled) = match (ftps, ftpes, http, https) {
		(true, false, false, false) => (Protocol::FtpImplicitTls, true),
		(false, true, false, false) => (Protocol::Ftp, true),
		(false, false, true, false) => (Protocol::WebDav, false),
		(false, false, false, true) => (Protocol::WebDavHttps, true),
		(false, false, false, false) if cert.is_some() || key.is_some() => (Protocol::Ftp, true),
		(false, false, false, false) => (Protocol::Ftp, false),
		_ => unreachable!("clap conflicts_with prevents invalid combinations"),
	};
	let implicit_tls = protocol.implicit_tls();

	// Default port: 990 (Implicit FTPS) / 443 (HTTPS) / 80 (HTTP) / 21 (FTP).
	let port = port.unwrap_or(match protocol {
		Protocol::FtpImplicitTls => 990,
		Protocol::WebDavHttps => 443,
		Protocol::WebDav => 80,
		Protocol::Ftp => 21,
	});

	// --- Parse bind address ---
	let is_loopback =
		bind == "127.0.0.1" || bind == "::1" || bind.eq_ignore_ascii_case("localhost");
	let bind_addr: std::net::SocketAddr = format!("{}:{}", bind, port)
		.parse()
		.map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("bad bind: {}", e)))?;

	// --- Auth config ---
	let auth = if is_loopback && user.is_none() {
		// Anonymous loopback — safe.
		eprintln!("[serve] anonymous mode (loopback only)");
		AuthConfig::no_auth()
	} else if !is_loopback && user.is_none() && !force {
		// Refuse to expose anonymously to the network unless --force is set.
		return Err(io::Error::new(
			io::ErrorKind::PermissionDenied,
			"Binding to a non-loopback address requires --user for authentication. \
			 Anonymous network exposure is refused. Use --force to override.",
		));
	} else if !is_loopback && user.is_none() && force {
		// Forced anonymous network exposure — user accepted the risk.
		eprintln!("[serve] WARNING: anonymous network exposure (--force)");
		eprintln!("[serve] WARNING: anyone on the network can read projected files");
		AuthConfig::no_auth()
	} else {
		// User specified — prompt for password interactively.
		let user = user.unwrap();
		let proto_name = if protocol.is_webdav() {
			"WebDAV"
		} else {
			"FTP"
		};
		eprintln!("[serve] {} user: {}", proto_name, user);
		let pass = get_user_password(&format!("{} password", proto_name), false)?;
		let auth = AuthConfig::with_credentials(user, pass.as_str());
		drop(pass);
		auth
	};

	// --- Scan all roots for encrypted files ---
	let scan_pb = ProgressBar::new_spinner();
	scan_pb.set_style(
		ProgressStyle::default_spinner()
			.template("{spinner:.green} Scanning for encrypted files... {pos} entries")
			.unwrap(),
	);
	scan_pb.enable_steady_tick(Duration::from_millis(100));
	let mut all_enc_files: Vec<(usize, PathBuf)> = Vec::new();
	for (i, root) in roots.iter().enumerate() {
		let (_nor_files, enc_files) = resolve_ne_path_from_dir_with_progress(root, |count| {
			scan_pb.set_position(count as u64);
		});
		for f in enc_files {
			all_enc_files.push((i, f));
		}
	}
	scan_pb.finish_with_message(format!(
		"Scan complete: {} encrypted file(s) found across {} root(s)",
		all_enc_files.len(),
		roots.len()
	));

	// --- Encryption password(s) with pre-verification ---
	//
	// If there are no encrypted files, no password is needed (plain files
	// are served as-is). Otherwise, prompt for the first password, then
	// verify every encrypted file can be opened with the current keyring.
	// If any file fails (wrong key), prompt for another password and retry
	// the still-failing files. The server only starts once ALL encrypted
	// files are verified — matching the `crypt` mode's password behaviour.
	let enc_paths: Vec<PathBuf> = all_enc_files.iter().map(|(_, p)| p.clone()).collect();
	let manager = if enc_paths.is_empty() {
		eprintln!("[serve] no encrypted files found — serving plain files only");
		Manager::new(true, true, 2048, is_supported_file, 6, None)
	} else {
		eprintln!(
			"[serve] {} encrypted file(s) require password verification",
			enc_paths.len()
		);
		let first_pwd = get_user_password("Encryption password", false)?;
		let mut mgr = Manager::new(
			true,
			true,
			2048,
			is_supported_file,
			6,
			Some(first_pwd.as_bytes()),
		);
		drop(first_pwd);
		verify_encryption_passwords(&enc_paths, &mut mgr)?;
		mgr
	};

	// --- Session key (memory encryption for cached heads) ---
	let session_key = Arc::new(SessionKey::generate());

	// --- Pre-populate projection cache  ---
	// Decrypt and cache every encrypted file's head eagerly at startup so
	// the first PROPFIND / directory listing is instant. Without this,
	// listing a directory with N encrypted files opens + decrypts all N
	// files on every first request, causing noticeable stutter.
	let cache = Arc::new(rcrm::serve::FileCache::new());
	if !all_enc_files.is_empty() {
		eprintln!(
			"[serve] pre-loading {} encrypted file(s) into cache...",
			all_enc_files.len()
		);
		let pb = ProgressBar::new(all_enc_files.len() as u64);
		pb.set_style(
			ProgressStyle::default_bar()
				.template("[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} caching {percent}%")
				.unwrap(),
		);
		for (mount_idx, f) in &all_enc_files {
			match cache.get_or_open(f, &manager, &session_key, *mount_idx) {
				Ok(_) => {}
				Err(e) => {
					eprintln!("[serve] warning: failed to cache {}: {}", f.display(), e);
				}
			}
			pb.inc(1);
		}
		pb.finish_with_message("Cache pre-load complete");
	}

	// --- TLS config ---
	let tls_cfg = if tls_enabled {
		let cfg = match (&cert, &key) {
			(Some(c), Some(k)) => {
				eprintln!("[serve] loading TLS cert from {} + key from {}", c, k);
				tls_config::build_config_from_pem_files(Path::new(c), Path::new(k))?
			}
			(None, None) => {
				eprintln!("[serve] generating ephemeral self-signed TLS certificate");
				tls_config::build_ephemeral_config()?
			}
			_ => {
				return Err(io::Error::new(
					io::ErrorKind::InvalidInput,
					"--cert and --key must be supplied together (or both omitted for auto-gen)",
				));
			}
		};
		Some(cfg)
	} else {
		None
	};

	if implicit_tls {
		eprintln!(
			"[serve] {} mode (implicit TLS — connection encrypted from byte 0)",
			if protocol.is_webdav() {
				"HTTPS WebDAV"
			} else {
				"implicit FTPS"
			}
		);
	} else if tls_enabled {
		eprintln!("[serve] explicit FTPS mode (AUTH TLS upgrade)");
	} else if protocol.is_webdav() {
		eprintln!("[serve] plain HTTP WebDAV mode (no TLS)");
	}

	// --- Build server context ---
	let ctx = ServerContext {
		mounts,
		manager: Arc::new(manager),
		session_key,
		cache,
		tls_config: tls_cfg,
		require_tls: false,
		implicit_tls,
		protocol,
		max_connections,
		auth,
		idle_timeout: Duration::from_secs(300),
	};

	let server = Server::new(ctx, bind_addr);

	// --- Ctrl+C handler for graceful shutdown ---
	let shutdown = Arc::new(AtomicBool::new(false));
	let shutdown_handler = Arc::clone(&shutdown);
	ctrlc::set_handler(move || {
		if !shutdown_handler.swap(true, Ordering::SeqCst) {
			eprintln!("\n[serve] shutdown requested — stopping (Ctrl+C again to force-kill)");
		} else {
			eprintln!("[serve] forcing immediate exit");
			std::process::exit(130);
		}
	})
	.map_err(|e| io::Error::other(format!("ctrlc handler: {}", e)))?;

	eprintln!(
		"[serve] roots: {}",
		roots.iter().map(|r| r.display().to_string()).collect::<Vec<_>>().join(", ")
	);
	eprintln!("[serve] press Ctrl+C to stop");
	server.run(shutdown)
}

/// Verify that every encrypted file in `enc_files` can be opened (header
/// verified) with at least one key currently registered in `manager`.
///
/// If any file fails with `InvalidData` (wrong key or corrupt header),
/// prompt for another password, add it to the manager, and retry only the
/// still-failing files. I/O errors (e.g. permission denied) are reported as
/// warnings but do not block verification — those files will simply fail at
/// serve time and be hidden from listings.
///
/// Returns `Ok(())` only when every encrypted file verifies. Returns `Err`
/// (with a descriptive message) if the user cancels by submitting an empty
/// password, in which case the server must NOT start.
fn verify_encryption_passwords(enc_files: &[PathBuf], manager: &mut Manager) -> io::Result<()> {
	// `pending` holds the files still needing verification. On each pass we
	// try all pending files; those that succeed are dropped, those that fail
	// with InvalidData stay in `pending` for the next round. Adding a new
	// key can only make more files pass, never fewer.
	let mut pending: Vec<&PathBuf> = enc_files.iter().collect();

	loop {
		let mut failed: Vec<&PathBuf> = Vec::new();
		let mut io_errors = 0usize;

		let pb = ProgressBar::new(pending.len() as u64);
		pb.set_style(
			ProgressStyle::default_bar()
				.template("[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} verifying ({msg})")
				.unwrap(),
		);

		for p in &pending {
			pb.set_message(
				p.file_name()
					.unwrap_or_default()
					.to_string_lossy()
					.into_owned(),
			);
			match std::fs::File::open(p) {
				Ok(mut f) => match manager.read_file_header_any_key(&mut f) {
					Ok(_) => {}
					Err(e) if e.kind() == io::ErrorKind::InvalidData => {
						failed.push(*p);
					}
					Err(_) => {
						io_errors += 1;
					}
				},
				Err(_) => {
					io_errors += 1;
				}
			}
			pb.inc(1);
		}
		pb.finish_and_clear();

		if io_errors > 0 {
			eprintln!(
				"[serve] warning: {} file(s) had I/O errors during verification (will be hidden at serve time)",
				io_errors
			);
		}

		if failed.is_empty() {
			eprintln!(
				"[serve] all {} encrypted file(s) verified successfully",
				enc_files.len()
			);
			return Ok(());
		}

		eprintln!(
			"[serve] {} of {} encrypted file(s) could not be decrypted with current password(s)",
			failed.len(),
			enc_files.len()
		);
		if let Some(example) = failed.first() {
			eprintln!("[serve] example: {}", example.display());
		}

		// Prompt for another password. Empty = cancel.
		let pwd = Password::new()
			.with_prompt("Enter another password (empty to cancel)")
			.allow_empty_password(true)
			.interact()?;

		if pwd.is_empty() {
			return Err(io::Error::new(
				io::ErrorKind::PermissionDenied,
				format!(
					"Password verification failed: {} of {} encrypted file(s) could not be decrypted. \
					 Server not started.",
					failed.len(),
					enc_files.len()
				),
			));
		}

		manager.use_added_key(pwd.as_bytes());
		pending = failed;
	}
}
