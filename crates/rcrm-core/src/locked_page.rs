// locked_page.rs
// Page-aligned, mlock'd memory for sensitive keys.
// On drop: zeroized, unlocked, freed.
//
// Linux/macOS: mmap(ANON|PRIVATE) + mlock
// Windows:     VirtualAlloc(MEM_COMMIT|RESERVE) + VirtualLock

use std::io;

// ── Platform-specific allocation ────────────────────────

#[cfg(unix)]
mod imp {
	use std::io;
	use std::ptr;

	pub fn alloc_locked(size: usize) -> io::Result<(*mut u8, usize)> {
		let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };
		let len = size.max(1).next_multiple_of(page_size);
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
		// 4096 is universal on modern Windows (x86/x64/ARM64).
		// GetSystemInfo would be more correct but adds complexity.
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

// ── LockedKey ───────────────────────────────────────────

/// A page-locked buffer holding a fixed-size secret.
///
/// The memory is allocated on a private, anonymous page, locked with
/// `mlock` (Unix) or `VirtualLock` (Windows) so it cannot be paged to
/// swap. On drop the contents are zeroized and the page released.
pub struct LockedKey<const N: usize> {
	ptr: *mut u8,
	page_len: usize,
}

// LockedKey wraps raw memory but the page is private and never aliased.
unsafe impl<const N: usize> Send for LockedKey<N> {}
unsafe impl<const N: usize> Sync for LockedKey<N> {}

impl<const N: usize> LockedKey<N> {
	/// Allocate a locked page and copy `data` into it.
	///
	/// # Errors
	/// Returns `io::Error` if allocation or locking fails.
	pub fn new(data: &[u8; N]) -> io::Result<Self> {
		let (ptr, page_len) = imp::alloc_locked(N)?;
		unsafe {
			ptr.copy_from_nonoverlapping(data.as_ptr(), N);
		}
		Ok(Self { ptr, page_len })
	}

	/// Allocate a locked page with zeroed memory. Caller writes key material
	/// directly into the locked page via [`as_mut_bytes`] — the key never
	/// touches the stack.
	///
	/// This is the OpenSSL `OPENSSL_secure_zalloc` pattern: allocate locked
	/// memory first, then write the secret into it.
	///
	/// # Errors
	/// Returns `io::Error` if allocation or locking fails.
	pub fn zeroed() -> io::Result<Self> {
		let (ptr, page_len) = imp::alloc_locked(N)?;
		// Memory from mmap(MAP_ANON) / VirtualAlloc is already zeroed.
		Ok(Self { ptr, page_len })
	}

	/// Borrow the key as `&[u8; N]`.
	#[inline]
	pub fn as_bytes(&self) -> &[u8; N] {
		// SAFETY: ptr was written with N bytes and never modified
		// (except zeroed on drop, at which point the reference is gone).
		unsafe { &*(self.ptr as *const [u8; N]) }
	}

	/// Mutably borrow the key as `&mut [u8; N]` for direct writes into
	/// locked memory. Used with `zeroed()` to write secrets without stack
	/// exposure.
	#[inline]
	pub fn as_mut_bytes(&mut self) -> &mut [u8; N] {
		// SAFETY: ptr points to a uniquely-owned locked page of page_len
		// bytes, with N ≤ page_len. The returned reference is valid for the
		// lifetime of &mut self.
		unsafe { &mut *(self.ptr as *mut [u8; N]) }
	}
}

impl<const N: usize> Clone for LockedKey<N> {
	fn clone(&self) -> Self {
		// Allocate a fresh locked page and copy the key material.
		// Each clone gets its own independently-locked page.
		Self::new(self.as_bytes()).expect("LockedKey clone allocation failed")
	}
}

impl<const N: usize> PartialEq for LockedKey<N> {
	fn eq(&self, other: &Self) -> bool {
		self.as_bytes() == other.as_bytes()
	}
}

impl<const N: usize> Eq for LockedKey<N> {}

impl<const N: usize> AsRef<[u8; N]> for LockedKey<N> {
	fn as_ref(&self) -> &[u8; N] {
		self.as_bytes()
	}
}

impl<const N: usize> Drop for LockedKey<N> {
	fn drop(&mut self) {
		// Zeroize
		unsafe {
			std::ptr::write_bytes(self.ptr, 0, N);
		}
		// Unlock + free
		unsafe {
			imp::free_locked(self.ptr, self.page_len);
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn new_stores_data() {
		let data = [0xAAu8; 32];
		let key = LockedKey::new(&data).expect("alloc_locked failed");
		assert_eq!(key.as_bytes(), &data);
	}

	#[test]
	fn different_values_roundtrip() {
		let mut data = [0u8; 32];
		for (i, b) in data.iter_mut().enumerate() {
			*b = i as u8;
		}
		let key = LockedKey::new(&data).expect("alloc_locked failed");
		assert_eq!(key.as_bytes(), &data);
	}

	#[test]
	fn zero_filled_roundtrip() {
		let data = [0u8; 16];
		let key = LockedKey::new(&data).expect("alloc_locked failed");
		assert_eq!(key.as_bytes(), &data);
	}

	#[test]
	fn single_byte_key() {
		let key = LockedKey::new(&[42u8]).expect("alloc_locked failed");
		assert_eq!(key.as_bytes(), &[42u8]);
	}

	#[test]
	fn large_key_64_bytes() {
		let data = [0x7Fu8; 64];
		let key = LockedKey::new(&data).expect("alloc_locked failed");
		assert_eq!(key.as_bytes(), &data);
	}

	#[test]
	fn drop_does_not_crash() {
		let data = [0u8; 32];
		let key = LockedKey::new(&data).expect("alloc_locked failed");
		drop(key);
		// If we reach here without segfault, the OS-level
		// munlock+munmap / VirtualUnlock+VirtualFree worked.
	}

	#[test]
	fn multiple_keys_independent() {
		let a = LockedKey::new(&[1u8; 32]).expect("alloc_locked failed");
		let b = LockedKey::new(&[2u8; 32]).expect("alloc_locked failed");
		assert_eq!(a.as_bytes(), &[1u8; 32]);
		assert_eq!(b.as_bytes(), &[2u8; 32]);
		drop(a);
		assert_eq!(b.as_bytes(), &[2u8; 32]);
	}
}
