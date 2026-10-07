// src/metadata.rs
// EXIF / track metadata for the media info panels, via `nom-exif`.
//
// Modular by design: this module owns one job — bytes in, documented JSON out.
// It knows nothing about decoding, HTTP or the UI, and the same entry point
// serves images (EXIF) and video/audio containers (track info), so the player
// can reuse it later without a second binding.
//
// The bytes always arrive from Dart (fetched over authenticated HTTP and
// decrypted in RAM), never from a file path: nothing plaintext touches disk.
//
// JSON shape (only fields that were actually found are present):
// {
//   "kind": "image" | "track",
//   "exif": {
//     "make", "model", "lens", "software",
//     "capturedAt": "YYYY-MM-DD HH:MM:SS", "capturedOffset": "+08:00",
//     "iso", "fNumber", "exposureTime" (seconds), "focalLength" (mm),
//     "focalLength35mm", "exposureBias" (EV), "flash" (bool),
//     "orientation", "pixelWidth", "pixelHeight",
//     "gps": { "lat", "lon", "altitude" (m) },
//     "embeddedTrack": bool
//   },
//   "track": {
//     "make", "model", "software", "author",
//     "durationMs", "width", "height",
//     "createdAt": "YYYY-MM-DD HH:MM:SS", "gpsIso6709"
//   },
//   "error": "..."        // only when the source could not be parsed at all
// }

use nom_exif::{
	EntryValue, Exif, ExifTag, MediaKind, MediaParser, MediaSource, TrackInfo, TrackInfoTag,
};
use serde_json::{Map, Value, json};

/// What the caller believes the bytes are. `Auto` trusts the container header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KindHint {
	#[default]
	Auto,
	Image,
	Track,
}

impl KindHint {
	pub fn from_code(code: u8) -> Self {
		match code {
			1 => Self::Image,
			2 => Self::Track,
			_ => Self::Auto,
		}
	}
}

/// Parse `bytes` and return the JSON document described in the module header.
///
/// Never fails hard: an unreadable source comes back as
/// `{"kind":"unknown","error":"…"}` so the UI has one shape to handle.
pub fn parse_json(bytes: Vec<u8>, hint: KindHint) -> String {
	match parse(bytes, hint) {
		Ok(value) => value.to_string(),
		Err(err) => json!({ "kind": "unknown", "error": err }).to_string(),
	}
}

fn parse(bytes: Vec<u8>, hint: KindHint) -> Result<Value, String> {
	let source = MediaSource::from_memory(bytes).map_err(|e| e.to_string())?;
	let detected = source.kind();
	let kind = match hint {
		KindHint::Auto => detected,
		KindHint::Image => MediaKind::Image,
		KindHint::Track => MediaKind::Track,
	};
	let mut parser = MediaParser::new();
	let mut out = Map::new();
	// A file that carries no metadata is not a failure — the section is just
	// empty. Only an unidentifiable container is an error (handled above).
	match kind {
		MediaKind::Image => {
			out.insert("kind".into(), json!("image"));
			match parser.parse_exif(source) {
				Ok(iter) => {
					let embedded_track = iter.has_embedded_track();
					let exif: Exif = iter.into();
					let summary = exif_summary(&exif, embedded_track);
					if !summary.is_empty() {
						out.insert("exif".into(), Value::Object(summary));
					}
				}
				Err(err) => {
					out.insert("error".into(), json!(err.to_string()));
				}
			}
		}
		MediaKind::Track => {
			out.insert("kind".into(), json!("track"));
			match parser.parse_track(source) {
				Ok(track) => {
					let summary = track_summary(&track);
					if !summary.is_empty() {
						out.insert("track".into(), Value::Object(summary));
					}
				}
				Err(err) => {
					out.insert("error".into(), json!(err.to_string()));
				}
			}
		}
	}
	Ok(Value::Object(out))
}

fn exif_summary(exif: &Exif, embedded_track: bool) -> Map<String, Value> {
	let mut out = Map::new();

	let text = |tag: ExifTag| -> Option<String> {
		exif.get(tag)
			.and_then(|v| v.as_str())
			.map(str::trim)
			.filter(|s| !s.is_empty())
			.map(str::to_owned)
	};
	let number = |tag: ExifTag| -> Option<f64> { exif.get(tag).and_then(entry_number) };
	let integer = |tag: ExifTag| -> Option<i64> {
		exif.get(tag)
			.and_then(entry_number)
			.map(|v| v.round() as i64)
	};

	insert_str(&mut out, "make", text(ExifTag::Make));
	insert_str(&mut out, "model", text(ExifTag::Model));
	insert_str(&mut out, "lens", text(ExifTag::LensModel));
	insert_str(&mut out, "software", text(ExifTag::Software));

	if let Some(dt) = exif
		.get(ExifTag::DateTimeOriginal)
		.and_then(EntryValue::as_datetime)
		.or_else(|| {
			exif.get(ExifTag::CreateDate)
				.and_then(EntryValue::as_datetime)
		}) {
		// `aware()` keeps the timezone only when the file carried one.
		match dt.aware() {
			Some(aware) => {
				out.insert("capturedAt".into(), json!(aware.naive_local().to_string()));
				out.insert("capturedOffset".into(), json!(aware.offset().to_string()));
			}
			None => {
				out.insert("capturedAt".into(), json!(dt.into_naive().to_string()));
			}
		}
	}

	insert_num(&mut out, "iso", integer(ExifTag::ISOSpeedRatings));
	insert_num(&mut out, "fNumber", number(ExifTag::FNumber));
	insert_num(&mut out, "exposureTime", number(ExifTag::ExposureTime));
	insert_num(&mut out, "focalLength", number(ExifTag::FocalLength));
	insert_num(
		&mut out,
		"focalLength35mm",
		integer(ExifTag::FocalLengthIn35mmFilm),
	);
	insert_num(&mut out, "exposureBias", number(ExifTag::ExposureBiasValue));
	insert_num(&mut out, "orientation", integer(ExifTag::Orientation));
	insert_num(&mut out, "pixelWidth", integer(ExifTag::ExifImageWidth));
	insert_num(&mut out, "pixelHeight", integer(ExifTag::ExifImageHeight));
	if let Some(flash) = integer(ExifTag::Flash) {
		out.insert("flash".into(), json!(flash & 0x1 == 1));
	}

	if let Some(gps) = exif.gps_info() {
		let lat = gps.latitude.to_decimal_degrees();
		let lon = gps.longitude.to_decimal_degrees();
		if let (Some(lat), Some(lon)) = (lat, lon) {
			let mut g = Map::new();
			// to_decimal_degrees() is a magnitude: the hemispheres carry the sign.
			let lat = if matches!(gps.latitude_ref, nom_exif::LatRef::South) {
				-lat
			} else {
				lat
			};
			let lon = if matches!(gps.longitude_ref, nom_exif::LonRef::West) {
				-lon
			} else {
				lon
			};
			g.insert("lat".into(), json!(lat));
			g.insert("lon".into(), json!(lon));
			if let Some(alt) = gps.altitude.meters() {
				g.insert("altitude".into(), json!(alt));
			}
			out.insert("gps".into(), Value::Object(g));
		}
	}

	if embedded_track {
		out.insert("embeddedTrack".into(), json!(true));
	}
	out
}

fn track_summary(track: &TrackInfo) -> Map<String, Value> {
	let mut out = Map::new();

	let text = |tag: TrackInfoTag| -> Option<String> {
		track
			.get(tag)
			.and_then(|v| v.as_str())
			.map(str::trim)
			.filter(|s| !s.is_empty())
			.map(str::to_owned)
	};
	let integer = |tag: TrackInfoTag| -> Option<i64> {
		track.get(tag).and_then(entry_number).map(|v| v.round() as i64)
	};

	insert_str(&mut out, "make", text(TrackInfoTag::Make));
	insert_str(&mut out, "model", text(TrackInfoTag::Model));
	insert_str(&mut out, "software", text(TrackInfoTag::Software));
	insert_str(&mut out, "author", text(TrackInfoTag::Author));
	insert_str(&mut out, "gpsIso6709", text(TrackInfoTag::GpsIso6709));
	insert_num(&mut out, "durationMs", integer(TrackInfoTag::DurationMs));
	insert_num(&mut out, "width", integer(TrackInfoTag::Width));
	insert_num(&mut out, "height", integer(TrackInfoTag::Height));
	if let Some(dt) = track
		.get(TrackInfoTag::CreateDate)
		.and_then(EntryValue::as_datetime)
	{
		let stamp = dt
			.aware()
			.map(|a| a.naive_local().to_string())
			.unwrap_or_else(|| dt.into_naive().to_string());
		out.insert("createdAt".into(), json!(stamp));
	}
	out
}

/// EXIF numbers arrive as whichever type the file used: widen integers and
/// rationals, since `as_f64` alone only matches a literal `F64`.
fn entry_number(value: &EntryValue) -> Option<f64> {
	value
		.as_f64()
		.or_else(|| value.try_as_integer().map(|i| i as f64))
		.or_else(|| value.as_urational().and_then(|r| r.to_f64()))
		.or_else(|| value.as_irational().and_then(|r| r.to_f64()))
}

fn insert_str(out: &mut Map<String, Value>, key: &str, value: Option<String>) {
	if let Some(v) = value {
		out.insert(key.into(), json!(v));
	}
}

fn insert_num(out: &mut Map<String, Value>, key: &str, value: Option<impl Into<Value>>) {
	if let Some(v) = value {
		out.insert(key.into(), v.into());
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	// ── Minimal little-endian JPEG + EXIF builder ──────────────────
	//
	// Synthetic on purpose: the test must run everywhere, without a binary
	// fixture and without ffmpeg. Layout follows the TIFF/EXIF spec: header,
	// IFD0, IFD0 data, ExifIFD, ExifIFD data, GPS IFD, GPS data.

	struct Ifd {
		entries: Vec<(u16, u16, u32, Vec<u8>)>, // tag, type, count, data
	}

	impl Ifd {
		fn new() -> Self {
			Self { entries: vec![] }
		}

		fn add(&mut self, tag: u16, typ: u16, count: u32, data: Vec<u8>) -> &mut Self {
			self.entries.push((tag, typ, count, data));
			self
		}

		fn ascii(&mut self, tag: u16, s: &str) -> &mut Self {
			let mut bytes = s.as_bytes().to_vec();
			bytes.push(0);
			let count = bytes.len() as u32;
			self.add(tag, 2, count, bytes)
		}

		fn short(&mut self, tag: u16, v: u16) -> &mut Self {
			self.add(tag, 3, 1, v.to_le_bytes().to_vec())
		}

		fn long(&mut self, tag: u16, v: u32) -> &mut Self {
			self.add(tag, 4, 1, v.to_le_bytes().to_vec())
		}

		fn rational(&mut self, tag: u16, num: u32, den: u32) -> &mut Self {
			let mut bytes = num.to_le_bytes().to_vec();
			bytes.extend_from_slice(&den.to_le_bytes());
			self.add(tag, 5, 1, bytes)
		}

		fn rationals(&mut self, tag: u16, values: &[(u32, u32)]) -> &mut Self {
			let mut bytes = Vec::new();
			for (num, den) in values {
				bytes.extend_from_slice(&num.to_le_bytes());
				bytes.extend_from_slice(&den.to_le_bytes());
			}
			self.add(tag, 5, values.len() as u32, bytes)
		}

		fn byte(&mut self, tag: u16, v: u8) -> &mut Self {
			self.add(tag, 1, 1, vec![v])
		}

		fn size(&self) -> u32 {
			2 + 12 * self.entries.len() as u32 + 4
		}

		fn data_size(&self) -> u32 {
			self.entries
				.iter()
				.map(|(_, _, _, data)| {
					if data.len() > 4 {
						align4(data.len()) as u32
					} else {
						0
					}
				})
				.sum()
		}

		/// Serialize at [offset], writing external data starting at
		/// `offset + size()`. Any entry whose value is a placeholder produced
		/// by `pending` is patched in by the caller first.
		fn write(&self, out: &mut Vec<u8>, offset: u32) {
			let mut data_cursor = offset + self.size();
			out.extend_from_slice(&(self.entries.len() as u16).to_le_bytes());
			let mut deferred: Vec<(u32, Vec<u8>)> = Vec::new();
			for (tag, typ, count, data) in &self.entries {
				out.extend_from_slice(&tag.to_le_bytes());
				out.extend_from_slice(&typ.to_le_bytes());
				out.extend_from_slice(&count.to_le_bytes());
				if data.len() > 4 {
					out.extend_from_slice(&data_cursor.to_le_bytes());
					deferred.push((data_cursor, data.clone()));
					data_cursor += align4(data.len()) as u32;
				} else {
					let mut inline = data.clone();
					inline.resize(4, 0);
					out.extend_from_slice(&inline);
				}
			}
			out.extend_from_slice(&0u32.to_le_bytes()); // no next IFD
			for (_, data) in deferred {
				out.extend_from_slice(&data);
				let pad = align4(data.len()) - data.len();
				out.extend(std::iter::repeat_n(0u8, pad));
			}
		}
	}

	const fn align4(n: usize) -> usize {
		(n + 3) & !3
	}

	/// A tiny JPEG carrying Make/Model/DateTimeOriginal/exposure/GPS.
	fn sample_jpeg() -> Vec<u8> {
		// Sizes are fixed by the entry lists below; compute the offsets first.
		let mut ifd0 = Ifd::new();
		ifd0.ascii(0x010f, "vivo") // Make
			.ascii(0x0110, "X100 Pro") // Model
			.short(0x0112, 6) // Orientation (rotate 90 CW)
			.ascii(0x0131, "rcrm-test") // Software
			.long(0x8769, 0); // ExifIFD pointer (patched below)

		let mut exif_ifd = Ifd::new();
		exif_ifd
			.ascii(0x9003, "2026:09:30 02:24:11") // DateTimeOriginal
			.rational(0x829d, 18, 10) // FNumber f/1.8
			.rational(0x829a, 1, 250) // ExposureTime 1/250 s
			.short(0x8827, 100) // ISOSpeedRatings
			.rational(0x920a, 260, 10) // FocalLength 26 mm
			.short(0xa405, 24) // FocalLengthIn35mmFilm
			.ascii(0xa434, "Vario-Test 26mm") // LensModel
			.long(0xa002, 1440) // ExifImageWidth
			.long(0xa003, 1000) // ExifImageHeight
			.long(0x8825, 0); // GPS IFD pointer (patched below)

		let mut gps_ifd = Ifd::new();
		gps_ifd
			.ascii(0x0001, "N")
			.rationals(0x0002, &[(22, 1), (30, 1), (0, 1)])
			.ascii(0x0003, "E")
			.rationals(0x0004, &[(114, 1), (3, 1), (0, 1)])
			.byte(0x0005, 0) // AltitudeRef: above sea level
			.rational(0x0006, 123, 10);

		let tiff_data_start = 8;
		let ifd0_at = tiff_data_start;
		let ifd0_data_at = ifd0_at + ifd0.size();
		let exif_ifd_at = ifd0_data_at + ifd0.data_size();
		let exif_data_at = exif_ifd_at + exif_ifd.size();
		let gps_ifd_at = exif_data_at + exif_ifd.data_size();

		// Patch the two pointers now that the layout is known.
		for e in ifd0.entries.iter_mut() {
			if e.0 == 0x8769 {
				e.3 = exif_ifd_at.to_le_bytes().to_vec();
			}
		}
		for e in exif_ifd.entries.iter_mut() {
			if e.0 == 0x8825 {
				e.3 = gps_ifd_at.to_le_bytes().to_vec();
			}
		}

		let mut tiff = Vec::new();
		tiff.extend_from_slice(b"II\x2a\x00");
		tiff.extend_from_slice(&tiff_data_start.to_le_bytes());
		assert_eq!(tiff.len() as u32, ifd0_at);
		ifd0.write(&mut tiff, ifd0_at);
		assert_eq!(tiff.len() as u32, exif_ifd_at);
		exif_ifd.write(&mut tiff, exif_ifd_at);
		assert_eq!(tiff.len() as u32, gps_ifd_at);
		gps_ifd.write(&mut tiff, gps_ifd_at);

		// Wrap in APP1 and a JPEG envelope.
		let mut app1 = Vec::new();
		app1.extend_from_slice(b"Exif\x00\x00");
		app1.extend_from_slice(&tiff);
		let mut jpeg = vec![0xff, 0xd8, 0xff, 0xe1];
		jpeg.extend_from_slice(&((app1.len() + 2) as u16).to_be_bytes());
		jpeg.extend_from_slice(&app1);
		jpeg.extend_from_slice(&[0xff, 0xd9]);
		jpeg
	}

	fn parse_sample() -> Value {
		let json = parse_json(sample_jpeg(), KindHint::Auto);
		serde_json::from_str(&json).expect("valid json")
	}

	#[test]
	fn reads_camera_exposure_and_datetime() {
		let v = parse_sample();
		assert_eq!(v["kind"], "image");
		let exif = &v["exif"];
		assert_eq!(exif["make"], "vivo");
		assert_eq!(exif["model"], "X100 Pro");
		assert_eq!(exif["lens"], "Vario-Test 26mm");
		assert_eq!(exif["software"], "rcrm-test");
		assert_eq!(exif["capturedAt"], "2026-09-30 02:24:11");
		assert_eq!(exif["iso"], 100);
		assert_eq!(exif["orientation"], 6);
		assert_eq!(exif["pixelWidth"], 1440);
		assert_eq!(exif["pixelHeight"], 1000);
		assert_eq!(exif["focalLength35mm"], 24);
		assert!((exif["fNumber"].as_f64().unwrap() - 1.8).abs() < 1e-9);
		assert!((exif["exposureTime"].as_f64().unwrap() - 1.0 / 250.0).abs() < 1e-9);
		assert!((exif["focalLength"].as_f64().unwrap() - 26.0).abs() < 1e-9);
	}

	#[test]
	fn reads_gps_with_hemisphere_signs() {
		let gps = &parse_sample()["exif"]["gps"];
		assert!((gps["lat"].as_f64().unwrap() - 22.5).abs() < 1e-6);
		assert!((gps["lon"].as_f64().unwrap() - 114.05).abs() < 1e-6);
		assert!((gps["altitude"].as_f64().unwrap() - 12.3).abs() < 1e-6);
	}

	#[test]
	fn unknown_bytes_report_an_error_instead_of_panicking() {
		let v: Value =
			serde_json::from_str(&parse_json(vec![0u8; 64], KindHint::Auto)).expect("json");
		assert_eq!(v["kind"], "unknown");
		assert!(v["error"].is_string());
	}

	#[test]
	fn empty_input_is_handled() {
		let v: Value = serde_json::from_str(&parse_json(Vec::new(), KindHint::Auto)).expect("json");
		assert_eq!(v["kind"], "unknown");
	}

	#[test]
	fn a_jpeg_without_exif_reports_no_metadata() {
		// SOI + APP0/JFIF + EOI: a real (if empty) JPEG envelope with no EXIF.
		let jpeg = vec![
			0xff, 0xd8, // SOI
			0xff, 0xe0, 0x00, 0x10, b'J', b'F', b'I', b'F', 0x00, 0x01, 0x01, 0x00, 0x00, 0x01,
			0x00, 0x01, 0x00, 0x00, // APP0
			0xff, 0xd9, // EOI
		];
		let v: Value =
			serde_json::from_str(&parse_json(jpeg, KindHint::Auto)).expect("json");
		assert_eq!(v["kind"], "image");
		assert!(v.get("exif").is_none(), "no EXIF means no exif object");
	}

	#[test]
	fn hint_overrides_the_container_guess() {
		// The bytes are a JPEG, but the caller insists they are a track: the
		// parse must go down the track path rather than silently succeeding
		// as an image.
		let v: Value = serde_json::from_str(&parse_json(
			sample_jpeg(),
			KindHint::Track,
		))
		.expect("json");
		assert_eq!(v["kind"], "track");
		assert!(v.get("exif").is_none());
	}

	#[test]
	fn kind_hint_codes_map_to_the_documented_values() {
		assert_eq!(KindHint::from_code(0), KindHint::Auto);
		assert_eq!(KindHint::from_code(1), KindHint::Image);
		assert_eq!(KindHint::from_code(2), KindHint::Track);
		assert_eq!(KindHint::from_code(9), KindHint::Auto);
	}
}
