//! Profile defaults, ownership of profile entries, and atomic template imports.
#[cfg(windows)]
mod startup;
use crate::list_registry::zapret_list_collection_empty;
use crate::logging::LogSink;
use std::{
    ffi::{CStr, c_char, c_void},
    mem::{size_of, swap},
    ptr,
};

const COLLECTIONS: usize = 9;
// Order of the explicit-value flags in desync_profile.
const IPV4_IPV6: usize = 8;

#[cfg(windows)]
#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn zapret_profile_report_status(
    status: u32,
    name: *const c_char,
    error: LogSink,
) -> bool {
    unsafe {
        match status {
            0 => return false,
            1 => error(c"desync_profile_add: out of memory\n".as_ptr()),
            2 => error(c"template '%s' already present\n".as_ptr(), name),
            3 => error(c"template '%s' not found\n".as_ptr(), name),
            4 => error(c"could not copy template\n".as_ptr()),
            _ => error(c"desync profile count out of range\n".as_ptr()),
        };
    }
    true
}

#[repr(C)]
struct Profile {
    number: u32,
    name: *mut c_char,
    cookie: *mut c_char,
    ipv4: bool,
    ipv6: bool,
    tcp: *mut c_void,
    udp: *mut c_void,
    icmp: *mut c_void,
    ip: *mut c_void,
    l7: u64,
    ips: *mut c_void,
    excluded_ips: *mut c_void,
    hosts: *mut c_void,
    excluded_hosts: *mut c_void,
    automatic: *mut c_void,
    fail_threshold: i32,
    fail_time: i32,
    retrans_threshold: i32,
    udp_in: i32,
    udp_out: i32,
    retrans_maxseq: u32,
    incoming_maxseq: u32,
    retrans_reset: bool,
    failures: *mut c_void,
    last_purge: i64,
    lua: *mut c_void,
    explicit: [bool; 10],
}

#[repr(C)]
struct Entry {
    profile: Profile,
    next: *mut Entry,
    previous: *mut *mut Entry,
}

pub(super) unsafe fn profile_number(profile: *const c_void) -> u32 {
    unsafe { (*profile.cast::<Profile>()).number }
}

pub(super) unsafe fn profile_name(profile: *const c_void) -> *const c_char {
    unsafe { (*profile.cast::<Profile>()).name }
}

pub(super) unsafe fn profile_display_name(profile: *const c_void) -> *const c_char {
    let name = unsafe { profile_name(profile) };
    if name.is_null() {
        c"noname".as_ptr()
    } else {
        name
    }
}

pub(super) unsafe fn profile_hosts_empty(profile: *const c_void) -> bool {
    let profile = profile.cast::<Profile>();
    unsafe {
        zapret_list_collection_empty((*profile).hosts.cast())
            && zapret_list_collection_empty((*profile).excluded_hosts.cast())
    }
}

#[cfg(windows)]
pub(super) unsafe fn profile_list_collection(
    profile: *const c_void,
    ip: bool,
    exclude: bool,
) -> *const crate::list_registry::Collection {
    let profile = profile.cast::<Profile>();
    unsafe {
        match (ip, exclude) {
            (false, false) => (*profile).hosts.cast(),
            (false, true) => (*profile).excluded_hosts.cast(),
            (true, false) => (*profile).ips.cast(),
            (true, true) => (*profile).excluded_ips.cast(),
        }
    }
}

#[cfg(windows)]
pub(super) unsafe fn profile_auto_host_file(
    profile: *const c_void,
) -> *const crate::list_registry::ListFile {
    unsafe { (*profile.cast::<Profile>()).automatic.cast() }
}

pub(super) unsafe fn profile_has_automatic_hosts(profile: *const c_void) -> bool {
    !unsafe { (*profile.cast::<Profile>()).automatic }.is_null()
}

#[cfg(target_pointer_width = "64")]
const _: () = {
    use std::mem::offset_of;
    assert!(offset_of!(Profile, hosts) == 88);
    assert!(offset_of!(Profile, excluded_hosts) == 96);
    assert!(offset_of!(Profile, automatic) == 104);
};

#[cfg(all(windows, target_pointer_width = "32"))]
const _: () = {
    use std::mem::offset_of;
    assert!(size_of::<Profile>() == 120 && align_of::<Profile>() == 8);
    assert!(offset_of!(Profile, l7) == 32 && offset_of!(Profile, ips) == 40);
    assert!(offset_of!(Profile, hosts) == 48 && offset_of!(Profile, excluded_hosts) == 52);
    assert!(offset_of!(Profile, automatic) == 56 && offset_of!(Profile, fail_threshold) == 60);
    assert!(offset_of!(Profile, retrans_reset) == 88 && offset_of!(Profile, failures) == 92);
    assert!(offset_of!(Profile, last_purge) == 96 && offset_of!(Profile, lua) == 104);
    assert!(offset_of!(Profile, explicit) == 108);
    assert!(size_of::<Entry>() == 128 && offset_of!(Entry, next) == 120);
};

#[cfg(windows)]
pub(super) unsafe fn profile_cookie(profile: *const c_void) -> *const c_char {
    unsafe { (*profile.cast::<Profile>()).cookie }
}

#[cfg(windows)]
pub(super) unsafe fn profile_lua(profile: *const c_void) -> *const c_void {
    unsafe { (*profile.cast::<Profile>()).lua }
}

#[cfg(windows)]
pub(super) unsafe fn profile_next(entry: *const c_void) -> *const c_void {
    unsafe { (*entry.cast::<Entry>()).next.cast() }
}

#[cfg(windows)]
#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_profile_ensure_automatic_hosts(
    mut entry: *mut Entry,
    ensure: unsafe extern "C" fn(*mut c_void),
) {
    while !entry.is_null() {
        let automatic = unsafe { (*entry).profile.automatic };
        if !automatic.is_null() {
            unsafe { ensure(automatic) };
        }
        entry = unsafe { (*entry).next };
    }
}

#[repr(C)]
struct Ops {
    allocate: unsafe extern "C" fn(usize) -> *mut c_void,
    release: unsafe extern "C" fn(*mut c_void),
    duplicate: unsafe extern "C" fn(*const c_char) -> *mut c_char,
    copy: unsafe extern "C" fn(u32, *mut *mut c_void, *const *mut c_void) -> bool,
    destroy: unsafe extern "C" fn(u32, *mut *mut c_void),
    failures: unsafe extern "C" fn(*mut *mut c_void),
    error: LogSink,
}

unsafe fn collection(profile: *mut Profile, index: usize) -> *mut *mut c_void {
    unsafe {
        match index {
            0 => ptr::addr_of_mut!((*profile).hosts),
            1 => ptr::addr_of_mut!((*profile).excluded_hosts),
            2 => ptr::addr_of_mut!((*profile).ips),
            3 => ptr::addr_of_mut!((*profile).excluded_ips),
            4 => ptr::addr_of_mut!((*profile).tcp),
            5 => ptr::addr_of_mut!((*profile).udp),
            6 => ptr::addr_of_mut!((*profile).icmp),
            7 => ptr::addr_of_mut!((*profile).ip),
            _ => ptr::addr_of_mut!((*profile).lua),
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_profile_init_dynamic(profile: *mut Profile) {
    for index in 0..COLLECTIONS {
        unsafe { collection(profile, index).write(ptr::null_mut()) };
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_profile_init(profile: *mut Profile) {
    unsafe {
        zapret_profile_init_dynamic(profile);
        (*profile).fail_threshold = 3;
        (*profile).fail_time = 60;
        (*profile).retrans_threshold = 3;
        (*profile).retrans_maxseq = 32_768;
        (*profile).incoming_maxseq = 4_096;
        (*profile).retrans_reset = true;
        (*profile).udp_out = 4;
        (*profile).udp_in = 1;
    }
}

unsafe fn clear_dynamic(profile: *mut Profile, ops: &Ops) {
    unsafe {
        (ops.release)((*profile).name.cast());
        (ops.release)((*profile).cookie.cast());
        for index in 0..COLLECTIONS {
            (ops.destroy)(index as u32, collection(profile, index));
        }
        (ops.failures)(ptr::addr_of_mut!((*profile).failures));
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_profile_clear(profile: *mut Profile, ops: &Ops) {
    unsafe {
        clear_dynamic(profile, ops);
        profile.write_bytes(0, 1)
    };
}

unsafe fn unlink(entry: *mut Entry) {
    unsafe {
        (*entry).previous.write((*entry).next);
        if !(*entry).next.is_null() {
            (*(*entry).next).previous = (*entry).previous;
        }
    }
}

unsafe fn append(head: *mut *mut Entry, entry: *mut Entry) {
    let mut tail = head;
    while !unsafe { tail.read() }.is_null() {
        tail = unsafe { ptr::addr_of_mut!((*tail.read()).next) };
    }
    unsafe {
        tail.write(entry);
        (*entry).previous = tail;
        (*entry).next = ptr::null_mut()
    };
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_profile_add(head: *mut *mut Entry, ops: &Ops) -> *mut Entry {
    let entry = unsafe { (ops.allocate)(size_of::<Entry>()) }.cast::<Entry>();
    if !entry.is_null() {
        unsafe {
            zapret_profile_init(ptr::addr_of_mut!((*entry).profile));
            append(head, entry)
        };
    }
    entry
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_profile_entry_destroy(entry: *mut Entry, ops: &Ops) {
    unsafe {
        clear_dynamic(ptr::addr_of_mut!((*entry).profile), ops);
        (ops.release)(entry.cast())
    };
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_profile_list_destroy(head: *mut *mut Entry, ops: &Ops) {
    while !unsafe { head.read() }.is_null() {
        let entry = unsafe { head.read() };
        unsafe {
            unlink(entry);
            zapret_profile_entry_destroy(entry, ops)
        };
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_profile_move(head: *mut *mut Entry, entry: *mut Entry) {
    unsafe {
        unlink(entry);
        append(head, entry)
    };
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_profile_search(
    mut entry: *mut Entry,
    name: *const c_char,
) -> *mut Entry {
    if name.is_null() {
        return ptr::null_mut();
    }
    let name = unsafe { CStr::from_ptr(name) };
    while !entry.is_null() {
        let candidate = unsafe { (*entry).profile.name };
        if !candidate.is_null() && unsafe { CStr::from_ptr(candidate) } == name {
            return entry;
        }
        entry = unsafe { (*entry).next };
    }
    ptr::null_mut()
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_profile_has_automatic(mut entry: *const Entry) -> bool {
    while !entry.is_null() {
        if !unsafe { (*entry).profile.automatic }.is_null() {
            return true;
        }
        entry = unsafe { (*entry).next };
    }
    false
}

unsafe fn copy_explicit(to: *mut Profile, from: *const Profile) {
    macro_rules! setting {
        ($index:literal, $field:ident) => {
            if unsafe { (*from).explicit[$index] } {
                unsafe {
                    (*to).$field = (*from).$field;
                    (*to).explicit[$index] = true;
                }
            }
        };
    }
    setting!(0, fail_threshold);
    setting!(1, fail_time);
    setting!(2, retrans_threshold);
    setting!(3, retrans_maxseq);
    setting!(4, incoming_maxseq);
    setting!(5, retrans_reset);
    setting!(6, udp_out);
    setting!(7, udp_in);
    setting!(9, l7);
    if unsafe { (*from).explicit[IPV4_IPV6] } {
        unsafe {
            if (*to).explicit[IPV4_IPV6] {
                (*to).ipv4 |= (*from).ipv4;
                (*to).ipv6 |= (*from).ipv6;
            } else {
                (*to).ipv4 = (*from).ipv4;
                (*to).ipv6 = (*from).ipv6;
                (*to).explicit[IPV4_IPV6] = true;
            }
        }
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_profile_import(
    to: *mut Profile,
    from: *const Profile,
    ops: &Ops,
) -> bool {
    if ptr::eq(to, from) {
        return true;
    }
    let source_auto = unsafe { (*from).automatic };
    if !source_auto.is_null()
        && !unsafe { (*to).automatic }.is_null()
        && unsafe { (*to).automatic } != source_auto
    {
        unsafe { (ops.error)(c"autohostlist replacement is not supported\n".as_ptr()) };
        return false;
    }
    let source_cookie = unsafe { (*from).cookie };
    let mut cookie = if source_cookie.is_null() {
        ptr::null_mut()
    } else {
        unsafe { (ops.duplicate)(source_cookie) }
    };
    if !source_cookie.is_null() && cookie.is_null() {
        return false;
    }
    let mut staged = [ptr::null_mut(); COLLECTIONS];
    let mut complete = true;
    for (index, slot) in staged.iter_mut().enumerate() {
        if !unsafe { (ops.copy)(index as u32, slot, collection(to, index)) }
            || !unsafe { (ops.copy)(index as u32, slot, collection(from.cast_mut(), index)) }
        {
            complete = false;
            break;
        }
    }
    if complete {
        unsafe { copy_explicit(to, from) };
        if !cookie.is_null() {
            unsafe { swap(&mut (*to).cookie, &mut cookie) };
        }
        if !source_auto.is_null() {
            unsafe { (*to).automatic = source_auto };
        }
        for (index, slot) in staged.iter_mut().enumerate() {
            let target = unsafe { collection(to, index) };
            unsafe {
                (ops.destroy)(index as u32, target);
                target.write(*slot);
                *slot = ptr::null_mut();
            }
            // Native BSD list nodes store a pointer back to the current
            // head. The opaque Rust host/IP collections have no such link.
            if index >= 4 && !unsafe { target.read() }.is_null() {
                let first = unsafe { target.read() }.cast::<u8>();
                let link = if index == 8 { 64 } else { 8 };
                unsafe {
                    first
                        .add(link + size_of::<usize>())
                        .cast::<*mut *mut c_void>()
                        .write(target)
                };
            }
        }
    }
    for (index, slot) in staged.iter_mut().enumerate() {
        unsafe { (ops.destroy)(index as u32, slot) };
    }
    unsafe { (ops.release)(cookie.cast()) };
    if !complete {
        unsafe { (ops.error)(c"dynamic structure copy failed\n".as_ptr()) };
    }
    complete
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_profile_filter_defaults(
    profile: *mut Profile,
    deny_empty: unsafe extern "C" fn(u32, *mut *mut c_void) -> bool,
) -> bool {
    if !unsafe { (*profile).explicit[IPV4_IPV6] } {
        unsafe {
            (*profile).ipv4 = true;
            (*profile).ipv6 = true
        };
    }
    if unsafe {
        !(*profile).tcp.is_null()
            || !(*profile).udp.is_null()
            || !(*profile).icmp.is_null()
            || !(*profile).ip.is_null()
    } {
        for index in 4..8 {
            if !unsafe { deny_empty(index as u32, collection(profile, index)) } {
                return false;
            }
        }
    }
    true
}

// The parser keeps its current profile in the production list until the next
// profile begins or parsing finishes. Allocation failure leaves both lists as-is.
#[repr(C)]
struct ProfileFlow {
    profiles: *mut *mut Entry,
    templates: *mut *mut Entry,
    current: *mut Entry,
    count: u32,
    template_count: u32,
    skip: bool,
    template: bool,
}

const FLOW_ALLOCATION: u32 = 1;
const FLOW_DUPLICATE: u32 = 2;
const FLOW_NO_TEMPLATE: u32 = 3;
const FLOW_IMPORT: u32 = 4;
const FLOW_COUNT: u32 = 5;

impl ProfileFlow {
    unsafe fn check_template(&self) -> Result<u32, u32> {
        let name = unsafe { (*self.current).profile.name };
        if !unsafe { zapret_profile_search(self.templates.read(), name) }.is_null() {
            return Err(FLOW_DUPLICATE);
        }
        self.template_count.checked_add(1).ok_or(FLOW_COUNT)
    }

    unsafe fn move_template(&mut self, number: u32) {
        unsafe {
            (*self.current).profile.number = number;
            zapret_profile_move(self.templates, self.current);
        }
        self.template_count = number;
    }

    unsafe fn next(&mut self, name: *const c_char, ops: &Ops) -> Result<(), u32> {
        let replacing = !self.current.is_null() && self.skip;
        let template_number = if !self.current.is_null() && self.template && !self.skip {
            Some(unsafe { self.check_template() }?)
        } else {
            None
        };
        let number = if replacing || template_number.is_some() {
            self.count
        } else {
            self.count.checked_add(1).ok_or(FLOW_COUNT)?
        };
        let label = unsafe { duplicate_label(name, ops) }?;
        if replacing {
            unsafe {
                let profile = ptr::addr_of_mut!((*self.current).profile);
                zapret_profile_clear(profile, ops);
                zapret_profile_init(profile);
            }
        } else {
            let entry = unsafe { zapret_profile_add(self.profiles, ops) };
            if entry.is_null() {
                unsafe { (ops.release)(label.cast()) };
                return Err(FLOW_ALLOCATION);
            }
            if let Some(number) = template_number {
                unsafe { self.move_template(number) };
            }
            self.current = entry;
        }
        unsafe {
            (*self.current).profile.name = label;
            (*self.current).profile.number = number;
        }
        self.count = number;
        self.skip = false;
        self.template = false;
        Ok(())
    }

    unsafe fn finish(&mut self, ops: &Ops) -> Result<(), u32> {
        if self.current.is_null() || !(self.skip || self.template) {
            return Ok(());
        }
        let count = self.count.checked_sub(1).ok_or(FLOW_COUNT)?;
        if self.skip {
            unsafe {
                unlink(self.current);
                zapret_profile_entry_destroy(self.current, ops);
            }
        } else {
            let number = unsafe { self.check_template() }?;
            unsafe { self.move_template(number) };
        }
        self.current = ptr::null_mut();
        self.count = count;
        Ok(())
    }
}

unsafe fn duplicate_label(name: *const c_char, ops: &Ops) -> Result<*mut c_char, u32> {
    if name.is_null() {
        return Ok(ptr::null_mut());
    }
    let label = unsafe { (ops.duplicate)(name) };
    if label.is_null() {
        Err(FLOW_ALLOCATION)
    } else {
        Ok(label)
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_profile_next(
    flow: &mut ProfileFlow,
    name: *const c_char,
    ops: &Ops,
) -> u32 {
    unsafe { flow.next(name, ops) }.err().unwrap_or(0)
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_profile_finish(flow: &mut ProfileFlow, ops: &Ops) -> u32 {
    unsafe { flow.finish(ops) }.err().unwrap_or(0)
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_profile_label(
    profile: *mut Profile,
    cookie: bool,
    name: *const c_char,
    ops: &Ops,
) -> u32 {
    if name.is_null() {
        return 0;
    }
    let label = match unsafe { duplicate_label(name, ops) } {
        Ok(label) => label,
        Err(code) => return code,
    };
    unsafe {
        let field = if cookie {
            &mut (*profile).cookie
        } else {
            &mut (*profile).name
        };
        (ops.release)(std::mem::replace(field, label).cast());
    }
    0
}

#[unsafe(no_mangle)]
unsafe extern "C" fn zapret_profile_import_named(
    flow: &ProfileFlow,
    name: *const c_char,
    ops: &Ops,
) -> u32 {
    let template = unsafe { zapret_profile_search(flow.templates.read(), name) };
    if template.is_null() {
        return FLOW_NO_TEMPLATE;
    }
    unsafe {
        let target = ptr::addr_of_mut!((*flow.current).profile);
        if !zapret_profile_import(target, ptr::addr_of!((*template).profile), ops) {
            return FLOW_IMPORT;
        }
        (*target).number = flow.count;
    }
    0
}
