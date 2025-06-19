use std::{ffi::OsStr, os::windows::ffi::OsStrExt, path::PathBuf, ptr};

use windows::Win32::System::ProcessStatus::K32GetModuleFileNameExW;
use windows::core::{PCSTR, PWSTR};
use windows::{
    Win32::{
        Foundation::CloseHandle,
        System::{
            Diagnostics::Debug::WriteProcessMemory,
            LibraryLoader::{GetModuleHandleW, GetProcAddress},
            Memory::{MEM_COMMIT, PAGE_READWRITE, VirtualAllocEx},
            Threading::{
                CREATE_SUSPENDED, CreateProcessW, CreateRemoteThread, PROCESS_INFORMATION,
                ResumeThread, STARTUPINFOW,
            },
        },
    },
    core::PCWSTR,
};

use crate::utils::get_base_dir;
use crate::utils::logging::{debug_print, error_message_box};
mod utils;

fn to_wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(Some(0)).collect()
}

fn path_to_pcwstr(path: &PathBuf) -> PCWSTR {
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    PCWSTR(wide.as_ptr())
}

fn print_target_process_name(process_handle: windows::Win32::Foundation::HANDLE) {
    let mut buf = [0u16; 260];
    unsafe {
        let len = K32GetModuleFileNameExW(Some(process_handle), None, &mut buf);
        if len == 0 {
            debug_print("[LOADER] Failed to get module name");
        } else {
            let exe = String::from_utf16_lossy(&buf[..len as usize]);
            debug_print(&format!("[LOADER] Confirmed target process image: {exe}"));
        }
    }
}

#[derive(Debug)]
pub enum LoaderError {
    General(String),
    WithProcessInfo(String, PROCESS_INFORMATION),
}

impl std::fmt::Display for LoaderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoaderError::General(msg) => write!(f, "{msg}"),
            LoaderError::WithProcessInfo(msg, _) => write!(f, "{msg} (with process info)"),
        }
    }
}

impl std::error::Error for LoaderError {}

fn run_loader() -> Result<(), LoaderError> {
    let base = get_base_dir();

    let game_path = base.join("P5R.exe");
    let dll_path = base.join("p5r_hooks.dll");

    debug_print(&format!(
        "[LOADER] Found game_path at {game_path:?} and dll_path at {dll_path:?}"
    ));

    // Create suspended process
    let si = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        ..Default::default()
    };

    let mut pi = PROCESS_INFORMATION::default();

    let mut command_line: Vec<u16> = to_wide(game_path.as_os_str());
    unsafe {
        CreateProcessW(
            None,
            Some(PWSTR(command_line.as_mut_ptr())),
            None,
            None,
            false,
            CREATE_SUSPENDED,
            None,
            path_to_pcwstr(&base),
            &si,
            &mut pi,
        )
    }
    .map_err(|e| LoaderError::General(format!("Failed to launch process: {e}")))?;

    // Inject DLL
    let dll_path_wide = to_wide(dll_path.as_os_str());
    let dll_len = (dll_path_wide.len() * 2) as usize;

    let remote_mem = unsafe {
        VirtualAllocEx(
            pi.hProcess,
            Some(ptr::null_mut()),
            dll_len,
            MEM_COMMIT,
            PAGE_READWRITE,
        )
    };

    if remote_mem.is_null() {
        return Err(LoaderError::WithProcessInfo(
            "Failed to allocate remote memory".into(),
            pi,
        ));
    }

    unsafe {
        WriteProcessMemory(
            pi.hProcess,
            remote_mem,
            dll_path_wide.as_ptr() as *const _,
            dll_len,
            Some(ptr::null_mut()),
        )
    }
    .map_err(|e| {
        LoaderError::WithProcessInfo(
            format!("Failed to write DLL path to process memory: {e}"),
            pi,
        )
    })?;

    let wide = to_wide("kernel32.dll".as_ref());

    let kernel32_handle = unsafe { GetModuleHandleW(PCWSTR(wide.as_ptr())) }.map_err(|e| {
        LoaderError::WithProcessInfo(format!("Failed to load kernel32.dll: {e:?}"), pi)
    })?;

    let load_library_addr =
        unsafe { GetProcAddress(kernel32_handle, PCSTR(b"LoadLibraryW\0".as_ptr())) }.ok_or_else(
            || LoaderError::WithProcessInfo("Could not find LoadLibraryW".into(), pi),
        )?;

    let thread_handle = unsafe {
        CreateRemoteThread(
            pi.hProcess,
            None,
            0,
            Some(std::mem::transmute(load_library_addr)),
            Some(remote_mem),
            0,
            None,
        )
    }
    .map_err(|e| {
        LoaderError::WithProcessInfo(format!("Failed to create remote thread: {e}"), pi)
    })?;

    unsafe {
        windows::Win32::System::Threading::WaitForSingleObject(thread_handle, u32::MAX);
        CloseHandle(thread_handle).expect("error closing remote thread handle");
    }

    print_target_process_name(pi.hProcess);

    // Resume the suspended game process
    unsafe {
        ResumeThread(pi.hThread);
        CloseHandle(pi.hProcess).expect("error closing hProcess");
        CloseHandle(pi.hThread).expect("error closing hThread");
    }

    debug_print("[LOADER] Injection successful.");
    Ok(())
}

fn main() {
    match run_loader() {
        Ok(()) => {
            debug_print("[LOADER] Success");
        }
        Err(LoaderError::WithProcessInfo(msg, pi)) => {
            error_message_box(&msg, "Persona 5 Royal Mod Loader");
            unsafe {
                CloseHandle(pi.hProcess).ok();
                CloseHandle(pi.hThread).ok();
            }
            debug_print(&msg);
        }
        Err(LoaderError::General(msg)) => {
            error_message_box(&msg, "Persona 5 Royal Mod Loader");
            debug_print(&msg);
        }
    }
}
