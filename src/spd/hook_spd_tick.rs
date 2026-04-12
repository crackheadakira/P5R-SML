use std::collections::HashMap;
use std::os::windows::raw::HANDLE;
use std::sync::RwLock;
use std::sync::atomic::{AtomicUsize, Ordering};

use once_cell::sync::Lazy;
use retour::static_detour;

use crate::scanner::{parse_pattern, scan_main_module};
use crate::vfs::apply_vfs_patches;
use crate::{CURRENT_GAME, TargetGame};
use crate::{hook, utils::logging::debug_print};

static GAME_ALLOC_PTR: AtomicUsize = AtomicUsize::new(0);

static_detour! {
    static Cri_Loader_Tick: unsafe extern "system" fn(HANDLE) -> u8;
}

type FnCriLoaderTick = unsafe extern "system" fn(HANDLE) -> u8;
type FnGameAlloc = unsafe extern "system" fn(usize) -> *mut u8;
type FnCompletionCallback = unsafe extern "system" fn(usize, HANDLE);

pub static ORIGINAL_CALLBACKS: Lazy<RwLock<HashMap<usize, usize>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

unsafe extern "C" {
    fn _aligned_malloc(size: usize, alignment: usize) -> *mut u8;
}

pub fn game_alloc(size: usize) -> *mut u8 {
    let addr = GAME_ALLOC_PTR.load(Ordering::SeqCst);

    if addr != 0 {
        unsafe {
            let f: FnGameAlloc = std::mem::transmute(addr);
            return f(size);
        }
    }

    unsafe {
        let ptr = _aligned_malloc(size, 16);

        if ptr.is_null() {
            crate::utils::logging::debug_print!(
                "[CRITICAL] _aligned_malloc failed to allocate {} bytes",
                size
            );
        }

        ptr
    }
}

pub unsafe extern "system" fn intercepted_callback(userdata: usize, loader: HANDLE) {
    let orig_cb = {
        let mut lock = ORIGINAL_CALLBACKS.write().unwrap();
        lock.remove(&(loader as usize))
    };

    unsafe { apply_vfs_patches(loader, userdata) };

    if let Some(cb) = orig_cb
        && cb != 0
    {
        let cb_fn: FnCompletionCallback = unsafe { std::mem::transmute(cb) };
        unsafe { cb_fn(userdata, loader) };
    }
}

fn p5r_hook_tick(loader: HANDLE) -> u8 {
    let base = loader as *mut u8;
    unsafe {
        let cb_ptr = base.add(0x158) as *mut usize;
        let current_cb = *cb_ptr;

        if current_cb != 0 && current_cb != (intercepted_callback as *const () as usize) {
            ORIGINAL_CALLBACKS
                .write()
                .unwrap()
                .insert(loader as usize, current_cb);
            *cb_ptr = intercepted_callback as *const () as usize;
        }
    }

    unsafe { Cri_Loader_Tick.call(loader) }
}

fn p4g_hook_tick(loader: HANDLE) -> u8 {
    let base = loader as *mut u8;

    unsafe {
        let cb_ptr = base.add(0x158) as *mut usize;
        let current_cb = *cb_ptr;
        if current_cb != 0 && current_cb != (intercepted_callback as *const () as usize) {
            ORIGINAL_CALLBACKS
                .write()
                .unwrap()
                .insert(loader as usize, current_cb);
            *cb_ptr = intercepted_callback as *const () as usize;
        }
    }

    let result = unsafe { Cri_Loader_Tick.call(loader) };

    unsafe {
        let current_cb = *(base.add(0x158) as *const usize);
        if current_cb == 0 {
            let status = *(base.add(0x1c) as *const i32);
            if status == 2 {
                let is_first_time = ORIGINAL_CALLBACKS
                    .write()
                    .unwrap()
                    .remove(&(loader as usize))
                    .is_some();

                if is_first_time {
                    let userdata = *(base.add(0x160) as *const usize);
                    apply_vfs_patches(loader, userdata);
                }
            }
        }
    }

    result
}

fn hook_impl(loader: HANDLE) -> u8 {
    match *CURRENT_GAME {
        TargetGame::P5R => p5r_hook_tick(loader),
        TargetGame::P4G => p4g_hook_tick(loader),
        TargetGame::Unknown => unsafe { Cri_Loader_Tick.call(loader) },
    }
}

pub fn register_hook() -> Result<(), Box<dyn std::error::Error>> {
    let loader_tick_pattern = "48 89 5c 24 ?? 55 56 57 41 54 41 55 41 56 41 57 48 83 ec 20 bd 01 00 00 00 48 8b f9 39 69 1c";

    unsafe {
        let parsed = parse_pattern(loader_tick_pattern);

        if let Some(address) = scan_main_module(&parsed) {
            let addr_usize = address as usize;

            debug_print!("[SCANNER] Found CriIoLoaderTick at {:#x}", addr_usize);

            hook!(FnCriLoaderTick, Cri_Loader_Tick, addr_usize, hook_impl);
        } else {
            return Err("Could not find pattern for CriIoLoaderTick".into());
        }
    }

    let game_alloc_pattern =
        "48 89 5c 24 ?? 57 48 83 ec 20 ba 10 00 00 00 48 8b f9 e8 ?? ?? ?? ?? 48 8b d8";

    unsafe {
        let parsed = parse_pattern(game_alloc_pattern);

        if let Some(address) = scan_main_module(&parsed) {
            let addr_usize = address as usize;

            debug_print!("[SCANNER] Found GameAlloc at {:#x}", addr_usize);

            GAME_ALLOC_PTR.store(addr_usize, Ordering::SeqCst);
        }
    }

    Ok(())
}
