// locked.rs — a minimal, private page-locked buffer for the pending password.
//
// Deliberately local to the bridge: rcrm-core keeps its LockedKey private, and
// exposing it just to hand a password across the crate boundary would widen the
// public API with Clone/Eq/AsRef the bridge never needs. This type has exactly
// three operations — zeroed(len), as_mut_ptr(), as_bytes() — and its Drop
// zeroizes + unlocks (the OpenSSL secure-heap contract: mlock so the secret
// never swaps, MADV_DONTDUMP so it stays out of core dumps, cleanse on free).
//
// No heap fallback: the core needs mlock for every derived key and the session
// key too, so a host that cannot lock one page cannot start the server at all.

use std::io;

use zeroize::Zeroize;

/// A page-locked, runtime-sized secret buffer. Zero-copy: the address handed
/// out by `as_mut_ptr` is stable for the buffer's whole lifetime, so Dart can
/// write into it directly and moving the struct copies no secret bytes.
pub struct LockedPassword {
	ptr: *mut u8,
	len: usize,
	page_len: usize,
}

// The page is private and uniquely owned; the address stays valid across moves.
unsafe impl Send for LockedPassword {}
unsafe impl Sync for LockedPassword {}

impl LockedPassword {
	/// Allocate a locked, zeroed buffer of `len` bytes.
	///
	/// # Errors
	/// Returns `io::Error` when allocation or locking fails (e.g. no
	/// `CAP_IPC_LOCK` on Linux) — the caller must refuse, not fall back to heap.
	pub fn zeroed(len: usize) -> io::Result<Self> {
		let (ptr, page_len) = imp::alloc_locked(len)?;
		Ok(Self { ptr, len, page_len })
	}

	/// Stable address for Dart to fill with exactly `len` bytes.
	#[inline]
	pub fn as_mut_ptr(&mut self) -> *mut u8 {
		self.ptr
	}

	/// Borrow the filled bytes.
	#[inline]
	pub fn as_bytes(&self) -> &[u8] {
		// SAFETY: `ptr` is a uniquely-owned locked allocation of at least `len`
		// bytes; no other reference into it is live while `&self` is held.
		unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
	}
}

impl Drop for LockedPassword {
	fn drop(&mut self) {
		// SAFETY: uniquely owned page; no reference outlives `&mut self`.
		unsafe {
			std::slice::from_raw_parts_mut(self.ptr, self.len).zeroize();
			imp::free_locked(self.ptr, self.page_len);
		}
	}
}

#[cfg(unix)]
mod imp {
	use std::io;
	use std::ptr;

	pub fn alloc_locked(size: usize) -> io::Result<(*mut u8, usize)> {
		let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };
		let len = size.max(1).next_multiple_of(page);
		let ptr = unsafe {
			libc::mmap(
				ptr::null_mut(),
				len,
				libc::PROT_READ | libc::PROT_WRITE,
				libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
				-1,
				0,
			)
		};
		if ptr == libc::MAP_FAILED {
			return Err(io::Error::last_os_error());
		}
		if unsafe { libc::mlock(ptr, len) } != 0 {
			let e = io::Error::last_os_error();
			unsafe { libc::munmap(ptr, len) };
			return Err(e);
		}
		// Keep the plaintext out of core dumps, like OpenSSL's secure heap.
		#[cfg(target_os = "linux")]
		unsafe {
			libc::madvise(ptr, len, libc::MADV_DONTDUMP);
		}
		Ok((ptr as *mut u8, len))
	}

	pub unsafe fn free_locked(ptr: *mut u8, len: usize) {
		unsafe {
			libc::munlock(ptr as *const _, len);
			libc::munmap(ptr as *mut _, len);
		}
	}
}

#[cfg(windows)]
mod imp {
	use std::io;
	use std::ptr;

	const MEM_COMMIT: u32 = 0x1000;
	const MEM_RESERVE: u32 = 0x2000;
	const MEM_RELEASE: u32 = 0x8000;
	const PAGE_READWRITE: u32 = 0x04;
	unsafe extern "system" {
		fn VirtualAlloc(
			lpAddress: *const core::ffi::c_void,
			dwSize: usize,
			flAllocationType: u32,
			flProtect: u32,
		) -> *mut core::ffi::c_void;
		fn VirtualFree(lpAddress: *mut core::ffi::c_void, dwSize: usize, dwFreeType: u32) -> i32;
		fn VirtualLock(lpAddress: *const core::ffi::c_void, dwSize: usize) -> i32;
		fn VirtualUnlock(lpAddress: *const core::ffi::c_void, dwSize: usize) -> i32;
	}

	pub fn alloc_locked(size: usize) -> io::Result<(*mut u8, usize)> {
		const PAGE_SIZE: usize = 4096;
		let len = size.max(1).next_multiple_of(PAGE_SIZE);
		let ptr =
			unsafe { VirtualAlloc(ptr::null(), len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) };
		if ptr.is_null() {
			return Err(io::Error::last_os_error());
		}
		if unsafe { VirtualLock(ptr, len) } == 0 {
			let e = io::Error::last_os_error();
			unsafe { VirtualFree(ptr, 0, MEM_RELEASE) };
			return Err(e);
		}
		Ok((ptr as *mut u8, len))
	}

	pub unsafe fn free_locked(ptr: *mut u8, len: usize) {
		unsafe {
			VirtualUnlock(ptr as *const _, len);
			VirtualFree(ptr as *mut _, 0, MEM_RELEASE);
		}
	}
}
