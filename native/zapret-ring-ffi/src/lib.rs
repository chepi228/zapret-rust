//! Versioned C ABI. Lua stack operations stay in C: no Lua longjmp crosses Rust.
use std::{
    cell::RefCell,
    ffi::c_void,
    panic::{AssertUnwindSafe, catch_unwind},
    rc::Rc,
    slice, str,
};
use zapret_ring::{
    self as ring, Context, Guard, HostIndex, Limits, SharedStore, Store, StoreScheduler,
};
mod api;
mod operations;
mod request;
pub use api::{Api, Response, Return};
pub use operations::{HOST_CAPACITY, OPERATIONS, STORE_EFFECT, STORE_SCHEDULER, STORE_STAT};
pub use request::{Request, STORE_HANDLE_PRESENT, STORE_HANDLE_SLOT};
enum Object {
    Store(SharedStore),
    Context(Context, StoreScheduler),
    Hosts(HostIndex),
}
type Checked<T> = Result<T, ()>;
impl Request {
    fn optional(&self, i: usize) -> Option<f64> {
        (self.present & (1 << i) != 0)
            .then_some(self.numbers[i])
            .filter(|n| n.is_finite())
    }
    fn number(&self, i: usize) -> Checked<f64> {
        self.optional(i).ok_or(())
    }
    fn unsigned(&self, i: usize) -> Checked<u64> {
        let n = self.number(i)?;
        if (0. ..=9_007_199_254_740_991.).contains(&n) && n.fract() == 0. {
            Ok(n as u64)
        } else {
            Err(())
        }
    }
    fn boolean(&self, i: usize) -> Checked<bool> {
        Ok(self.number(i)? != 0.)
    }
    unsafe fn bytes(&self, i: usize) -> Checked<Option<&[u8]>> {
        if self.text_present & (1 << i) == 0 {
            return Ok(None);
        }
        if self.lengths[i] > ring::MAX_BYTES || (self.lengths[i] > 0 && self.strings[i].is_null()) {
            return Err(());
        }
        Ok(Some(if self.lengths[i] == 0 {
            &[]
        } else {
            unsafe { slice::from_raw_parts(self.strings[i], self.lengths[i]) }
        }))
    }
    unsafe fn text(&self, i: usize) -> Checked<Option<&str>> {
        unsafe { self.bytes(i)? }
            .map(str::from_utf8)
            .transpose()
            .map_err(|_| ())
    }
    unsafe fn required_text(&self, i: usize) -> Checked<&str> {
        unsafe { self.text(i)? }.ok_or(())
    }
}
struct Output<'a> {
    response: &'a mut Response,
    buffer: &'a mut [u8],
    used: usize,
}
impl Output<'_> {
    fn push(&mut self, value: Return) -> Checked<()> {
        let i = self.response.count as usize;
        if i >= 8 {
            return Err(());
        }
        self.response.values[i] = value;
        self.response.count += 1;
        Ok(())
    }
    fn nil(&mut self) -> Checked<()> {
        self.push(Return::default())
    }
    fn number(&mut self, number: f64) -> Checked<()> {
        if !number.is_finite() {
            return Err(());
        }
        self.push(Return {
            kind: 1,
            number,
            ..Default::default()
        })
    }
    fn boolean(&mut self, value: bool) -> Checked<()> {
        self.push(Return {
            kind: 2,
            number: if value { 1. } else { 0. },
            ..Default::default()
        })
    }
    fn bytes(&mut self, bytes: &[u8]) -> Checked<()> {
        let end = self.used.checked_add(bytes.len()).ok_or(())?;
        if end > self.buffer.len() {
            return Err(());
        }
        self.buffer[self.used..end].copy_from_slice(bytes);
        let start = self.used;
        self.used = end;
        self.push(Return {
            kind: 3,
            offset: start,
            length: bytes.len(),
            ..Default::default()
        })
    }
    fn text(&mut self, text: Option<&str>) -> Checked<()> {
        if let Some(text) = text {
            self.bytes(text.as_bytes())
        } else {
            self.nil()
        }
    }
    fn optional(&mut self, value: Option<f64>) -> Checked<()> {
        if let Some(value) = value {
            self.number(value)
        } else {
            self.nil()
        }
    }

    fn store_stat(&mut self, store: &Store, stat: ring::store_effects::Stat) -> Checked<()> {
        use ring::store_effects::Stat;
        match stat {
            Stat::Count => self.number(store.len() as f64),
            Stat::Dirty => self.boolean(store.dirty),
            Stat::Disabled => self.boolean(store.disabled),
            Stat::Serial => self.number(store.serial as f64),
        }
    }
}
unsafe fn checked(op: u32, handle: *mut c_void, r: &Request, out: &mut Output<'_>) -> Checked<()> {
    let context = |handle: *mut c_void| -> Checked<&mut Context> {
        match unsafe { handle.cast::<Object>().as_mut() } {
            Some(Object::Context(ctx, _)) => Ok(ctx),
            _ => Err(()),
        }
    };
    let store = |handle: *mut c_void| -> Checked<&SharedStore> {
        match unsafe { handle.cast::<Object>().as_ref() } {
            Some(Object::Store(store)) => Ok(store),
            _ => Err(()),
        }
    };
    let hosts = |handle: *mut c_void| -> Checked<&mut HostIndex> {
        match unsafe { handle.cast::<Object>().as_mut() } {
            Some(Object::Hosts(hosts)) => Ok(hosts),
            _ => Err(()),
        }
    };
    match op {
        1 => {
            let limits = Limits {
                records: r.unsigned(0)? as usize,
                bytes: r.unsigned(1)? as usize,
                ttl: r.unsigned(2)?,
            };
            let mut s = Store::new(limits, r.boolean(3)?).ok_or(())?;
            s.legacy = r.optional(6).is_some_and(|n| n != 0.);
            if let Some(bytes) = unsafe { r.bytes(4)? } {
                s.load(bytes, r.unsigned(5)?);
            }
            out.response.object =
                Box::into_raw(Box::new(Object::Store(Rc::new(RefCell::new(s))))).cast();
        }
        2 => {
            let n = store(handle)?.borrow_mut().get(
                unsafe { r.required_text(1)? },
                r.unsigned(2)?,
                r.number(3)?,
            );
            out.optional(n.map(f64::from))?;
        }
        3 => {
            let n = r
                .optional(2)
                .map(|n| {
                    if (2. ..=128.).contains(&n) && n.fract() == 0. {
                        Ok(n as u32)
                    } else {
                        Err(())
                    }
                })
                .transpose()?;
            out.boolean(store(handle)?.borrow_mut().put(
                unsafe { r.required_text(1)? },
                n,
                r.unsigned(3)?,
                r.number(4)?,
            ))?;
        }
        4 => out.bytes(&store(handle)?.borrow_mut().snapshot(r.unsigned(1)?))?,
        5 => out.optional(store(handle)?.borrow_mut().due(r.number(1)?))?,
        6 => store(handle)?
            .borrow_mut()
            .commit(r.boolean(1)?, r.number(2)?),
        7 => store(handle)?.borrow_mut().discard(),
        8 => {
            let s = store(handle)?.borrow();
            for stat in ring::store_effects::STATS {
                out.store_stat(&s, stat)?;
            }
        }
        9 => {
            out.response.object = Box::into_raw(Box::new(Object::Context(
                Context::new(r.unsigned(0)?),
                StoreScheduler::default(),
            )))
            .cast();
        }
        10 => {
            let ctx = context(handle)?;
            let mono = r.number(1)?;
            out.boolean(if r.boolean(3)? {
                ctx.link_due(mono)
            } else {
                ctx.network_due(mono, r.boolean(2)?)
            })?;
        }
        11 => {
            let ctx = context(handle)?;
            let text = unsafe { r.text(1)? };
            let now = r.unsigned(2)?;
            let mono = r.number(3)?;
            if r.boolean(4)? {
                ctx.observe_link(text, now, mono)
            } else {
                ctx.observe_network(text, now, mono)
            };
        }
        12 => {
            let ctx = context(handle)?;
            out.text(ctx.network_for(unsafe { r.required_text(1)? }))?;
            out.number(ctx.network_revision as f64)?;
            out.number(ctx.epoch as f64)?;
            out.number(ctx.link_revision as f64)?;
            out.boolean(ctx.paused(r.number(2)?))?;
        }
        13 => {
            let now = r.unsigned(1)?;
            let started = r.optional(2).map(|n| n as u64);
            let net = unsafe { r.text(0)? }.and_then(|text| ring::network_key(text, now, started));
            if let Some(net) = net {
                out.text(Some(&net.key))?;
                out.text(Some(&net.composition))?;
            } else {
                out.nil()?;
            }
        }
        14 => {
            let now = r.unsigned(1)?;
            let started = r.optional(2).map(|n| n as u64);
            let lease = unsafe { r.text(0)? }.and_then(|text| ring::link_guard(text, now, started));
            if let Some(lease) = lease {
                out.number(lease.event as f64)?;
                out.number(lease.until as f64)?;
                out.number(lease.stamp as f64)?;
            } else {
                out.nil()?;
            }
        }
        15 => {
            let result = ring::state_path(
                unsafe { r.required_text(0)? },
                unsafe { r.required_text(1)? },
                unsafe { r.required_text(2)? },
            );
            out.text(result.as_deref())?;
        }
        16 => {
            let result = ring::subnet(unsafe { r.bytes(0)? }.ok_or(())?);
            out.text(result.as_deref())?;
        }
        17 => out.number(ring::received_ack(
            r.boolean(0)?,
            r.boolean(1)?,
            r.unsigned(2)? as u32,
            r.unsigned(3)? as u32,
        ) as f64)?,
        18 => out.boolean(ring::forged_rst(
            r.boolean(0)?,
            r.boolean(1)?,
            r.boolean(2)?,
            r.optional(3),
            r.optional(4),
            r.optional(5),
        ))?,
        19 => out.boolean(ring::tls_refused(
            r.boolean(0)?,
            r.boolean(1)?,
            r.boolean(2)?,
            r.boolean(3)?,
            r.number(4)?,
            r.number(5)?,
            r.number(6)?,
        ))?,
        20 => {
            let (ok, proved) = ring::success(
                r.boolean(0)?,
                r.boolean(1)?,
                r.boolean(2)?,
                r.unsigned(3)? as u32,
                r.optional(4),
            );
            out.boolean(ok)?;
            out.boolean(proved)?;
        }
        21 => {
            let (failed, count) =
                ring::failure(r.boolean(0)?, r.boolean(1)?, r.boolean(2)?, r.optional(3));
            out.boolean(failed)?;
            out.optional(count)?;
        }
        22 => {
            let (selected, reset) = ring::initial_strategy(
                r.unsigned(0)? as u32,
                r.optional(1).map(|n| n as u32),
                r.boolean(2)?,
                r.optional(3).map(|n| n as u64),
                r.unsigned(4)?,
                r.boolean(5)?,
                r.optional(6).map(|n| n as u32),
            );
            out.number(selected as f64)?;
            out.boolean(reset)?;
        }
        23 => {
            let mut guard = Guard {
                link_revision: r.optional(2).map(|n| n as u64),
                link_tainted: r.boolean(3)?,
            };
            let skip = guard.skip(ring::Observation {
                nocheck: r.boolean(0)?,
                evicted: r.boolean(1)?,
                link_revision: r.unsigned(4)?,
                paused: r.boolean(5)?,
                revision: r.optional(6).map(|n| n as u64),
                current_revision: r.unsigned(7)?,
                strategy: r.optional(8).map(|n| n as u32),
                current_strategy: r.optional(9).map(|n| n as u32),
            });
            out.boolean(skip)?;
            out.optional(guard.link_revision.map(|n| n as f64))?;
            out.boolean(guard.link_tainted)?;
        }
        24 => {
            out.boolean(context(handle)?.timer_gate(r.number(1)?, r.optional(2).map(|n| n != 0.)))?
        }
        25 => {
            out.response.object = Box::into_raw(Box::new(Object::Hosts(
                HostIndex::new(r.unsigned(0)? as usize).ok_or(())?,
            )))
            .cast();
        }
        26 => {
            let (id, evicted, created) = hosts(handle)?
                .access(unsafe { r.required_text(1)? }, unsafe {
                    r.required_text(2)?
                })
                .ok_or(())?;
            out.number(id as f64)?;
            out.optional(evicted.map(|n| n as f64))?;
            out.boolean(created)?;
        }
        27 => out.boolean(hosts(handle)?.touch(r.unsigned(1)?))?,
        28 => out.number(hosts(handle)?.len() as f64)?,
        29 => {
            let result = ring::legacy_state_path(unsafe { r.required_text(0)? }, unsafe {
                r.required_text(1)?
            });
            out.text(result.as_deref())?;
        }
        30 => {
            let ctx = context(handle)?;
            let state = unsafe { r.required_text(1)? };
            let mono = r.number(2)?;
            out.boolean(if r.boolean(4)? {
                ctx.link_due(mono)
            } else {
                ctx.network_due(mono, r.boolean(3)?)
            })?;
            out.text(ctx.network_for(state))?;
            out.number(ctx.network_revision as f64)?;
            out.number(ctx.epoch as f64)?;
            out.number(ctx.link_revision as f64)?;
            out.boolean(ctx.paused(mono))?;
        }
        31 => {
            // The engine's LuaJIT u32add converts to a signed integer first.
            let sequence = r.number(0)?.trunc();
            let limit = f64::from(u32::MAX);
            if !(-limit..=limit).contains(&sequence) {
                return Err(());
            }
            let (sequence, add_md5) = ring::tcp_fallback(sequence as i64 as u32, r.boolean(1)?);
            out.number(f64::from(sequence))?;
            out.boolean(add_md5)?;
        }
        32 => {
            let length = r.unsigned(0)? as usize;
            let start = r.unsigned(1)? as usize;
            let end = r.unsigned(2)? as usize;
            for range in ring::host_split(length, start, end).ok_or(())? {
                out.number(range.start as f64)?;
                out.number(range.end as f64)?;
            }
        }
        33 => out.boolean(ring::windows_absolute_path(unsafe { r.required_text(0)? }))?,
        STORE_SCHEDULER => {
            let event = unsafe { r.required_text(1)? };
            if event == "probe" && handle.is_null() {
                return out.boolean(true);
            }
            let store_operand = || {
                let arg = r.strings[STORE_HANDLE_SLOT].cast_mut().cast();
                if r.text_present & STORE_HANDLE_PRESENT == 0 || arg == handle {
                    return Err(());
                }
                store(arg)
            };
            let Some(Object::Context(context, scheduler)) =
                (unsafe { handle.cast::<Object>().as_mut() })
            else {
                return Err(());
            };
            match event {
                "probe" => out.boolean(true)?,
                "updated" | "prepare_update" => {
                    let store = store_operand()?;
                    let legacy_file = r.optional(3).is_some_and(|value| value != 0.)
                        && r.optional(4).is_some_and(|value| value != 0.);
                    let changed = r.optional(5).is_some_and(|value| value != 0.);
                    let (write, serial) = if event == "updated" {
                        scheduler.updated(store, legacy_file, changed)
                    } else {
                        scheduler.plan_update(store, legacy_file, changed)
                    };
                    out.boolean(write)?;
                    out.optional(serial.map(|serial| serial as f64))?;
                }
                "retain" => out.boolean(scheduler.retain(store_operand()?))?,
                "discard" => out.optional(
                    scheduler
                        .discard(store_operand()?)
                        .map(|serial| serial as f64),
                )?,
                "finish" => out.optional(
                    scheduler
                        .finish(store_operand()?)
                        .map(|serial| serial as f64),
                )?,
                "wants_timer" => out.boolean(scheduler.wants_timer())?,
                "prepare_timer" => out.boolean(scheduler.prepare_timer(context, r.number(2)?))?,
                "timer_result" => {
                    out.number(scheduler.timer_result(context, r.number(2)?, r.boolean(3)?) as f64)?
                }
                "fired" => scheduler.timer_fired(),
                "select" => {
                    out.optional(scheduler.select(r.number(2)?).map(|serial| serial as f64))?
                }
                "retired" => out.optional(scheduler.retired().map(|serial| serial as f64))?,
                "clear" => scheduler.clear(),
                _ => return Err(()),
            }
        }
        STORE_EFFECT => unsafe { store_effect(r, out) }?,
        STORE_STAT => {
            let stat = ring::store_effects::stat(r.unsigned(1)? as usize).ok_or(())?;
            out.store_stat(&store(handle)?.borrow(), stat)?;
        }
        HOST_CAPACITY => out.optional(ring::host_capacity(r.boolean(0)?, r.optional(1)))?,
        _ => return Err(()),
    }
    Ok(())
}

unsafe fn store_effect(request: &Request, out: &mut Output<'_>) -> Checked<()> {
    use ring::store_effects as effect;
    let event = unsafe { request.required_text(0)? };
    match event {
        "probe" => out.number(1.)?,
        "metadata" => {
            out.text(Some(effect::LIMIT_ERROR))?;
            out.text(Some(effect::TEMP_SUFFIX))?;
            out.text(Some(effect::TIMER_NAME))?;
            out.number(f64::from(effect::TIMER_INTERVAL))?;
            out.boolean(true)?;
            out.text(Some(effect::LOG_PREFIX))?;
            out.text(Some(&format!("; retry in {:.0}s", ring::RETRY_DELAY)))?;
        }
        "schema" => {
            for name in effect::schema_names() {
                out.text(Some(name))?;
            }
        }
        "limit_name" => out.text(effect::limit_name(request.unsigned(1)? as usize))?,
        "limit" => out.optional(effect::limit(
            request.unsigned(1)? as usize,
            request.boolean(2)?,
            request.optional(3),
        ))?,
        "stat_name" => out.text(effect::stat_name(request.unsigned(1)? as usize))?,
        "construct" => out.text(effect::construct_next(
            unsafe { request.text(1)? },
            request.boolean(2)?,
        ))?,
        "construction" => {
            let (read, file) = effect::construction(request.boolean(1)?, request.boolean(2)?);
            out.boolean(read)?;
            out.boolean(file)?;
        }
        "initial_file" => out.text(effect::initial_file(
            request.boolean(1)?,
            request.boolean(2)?,
            request.unsigned(3)? as usize,
            request.unsigned(4)? as usize,
        ))?,
        "key" => out.text(effect::key_check(
            request.boolean(1)?,
            request.boolean(2)?,
            request.unsigned(3)? as usize,
        ))?,
        "value" => out.boolean(effect::put_value(
            request.boolean(1)?,
            request.boolean(2)?,
            request.optional(3),
        ))?,
        "atomic" => {
            let (step, message) = effect::atomic_next(
                unsafe { request.text(1)? },
                request.boolean(2)?,
                request.boolean(3)?,
            );
            out.text(step)?;
            out.text(message)?;
        }
        "publish" => out.text(effect::publish_next(
            unsafe { request.text(1)? },
            request.boolean(2)?,
            request.boolean(3)?,
        ))?,
        "after" => out.text(effect::after_next(
            unsafe { request.required_text(1)? },
            unsafe { request.text(2)? },
            request.boolean(3)?,
        ))?,
        "after_plan" => {
            for action in
                effect::after_plan(unsafe { request.required_text(1)? }, request.boolean(2)?)
            {
                out.text(action)?;
            }
        }
        "timer_success" => out.boolean(effect::timer_success(
            request.boolean(1)?,
            request.boolean(2)?,
        ))?,
        "timer_check" => out.text(effect::timer_check(request.boolean(1)?))?,
        _ => return Err(()),
    }
    Ok(())
}

unsafe extern "C" fn invoke(
    op: u32,
    handle: *mut c_void,
    request: *const Request,
    response: *mut Response,
    buffer: *mut u8,
    capacity: usize,
) -> i32 {
    if request.is_null()
        || response.is_null()
        || capacity > ring::MAX_BYTES
        || (capacity > 0 && buffer.is_null())
    {
        return -1;
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        let r = unsafe { &*request };
        let response = unsafe { &mut *response };
        *response = Response::default();
        let bytes = if capacity == 0 {
            &mut []
        } else {
            unsafe { slice::from_raw_parts_mut(buffer, capacity) }
        };
        unsafe {
            checked(
                op,
                handle,
                r,
                &mut Output {
                    response,
                    buffer: bytes,
                    used: 0,
                },
            )
        }
    }));
    match result {
        Ok(Ok(())) => 0,
        Ok(Err(())) => -2,
        Err(_) => -3,
    }
}
unsafe extern "C" fn drop_object(handle: *mut c_void) {
    if !handle.is_null() {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            drop(unsafe { Box::from_raw(handle.cast::<Object>()) });
        }));
    }
}
static API: Api = Api {
    size: std::mem::size_of::<Api>(),
    version: 1,
    invoke,
    drop_object,
};
#[unsafe(no_mangle)]
pub extern "C" fn zapret_ring_api_v1() -> *const Api {
    &API
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn abi_layout_validation_and_typed_handles_remain_stable() {
        #[cfg(target_pointer_width = "64")]
        let expected = (400, 32, 272, 32);
        #[cfg(all(windows, target_pointer_width = "32"))]
        let expected = (272, 24, 208, 16);
        #[cfg(any(target_pointer_width = "64", all(windows, target_pointer_width = "32")))]
        assert_eq!(
            (
                std::mem::size_of::<Request>(),
                std::mem::size_of::<Return>(),
                std::mem::size_of::<Response>(),
                std::mem::size_of::<Api>(),
            ),
            expected,
        );
        let mut request = Request {
            numbers: [0.; 16],
            present: 1,
            strings: [std::ptr::null(); 16],
            lengths: [0; 16],
            text_present: 0,
        };
        request.numbers[0] = 2.;
        let mut response = Response::default();
        let mut buffer = [0; 512];
        let call = |op, handle, request, response, buffer: &mut [u8]| unsafe {
            (API.invoke)(
                op,
                handle,
                request,
                response,
                buffer.as_mut_ptr(),
                buffer.len(),
            )
        };
        assert_eq!(
            call(
                25,
                std::ptr::null_mut(),
                &request,
                &mut response,
                &mut buffer
            ),
            0
        );
        let handle = response.object;
        assert!(!handle.is_null());
        assert_eq!(call(28, handle, &request, &mut response, &mut buffer), 0);
        assert_eq!(response.values[0].number, 0.);
        assert_eq!(call(8, handle, &request, &mut response, &mut buffer), -2);
        assert_eq!(response.count, 0);
        assert_eq!(
            call(
                999,
                std::ptr::null_mut(),
                &request,
                &mut response,
                &mut buffer
            ),
            -2
        );
        assert_eq!(
            call(
                25,
                std::ptr::null_mut(),
                std::ptr::null(),
                &mut response,
                &mut buffer
            ),
            -1
        );
        unsafe { (API.drop_object)(handle) };
        request.numbers[0] = f64::NAN;
        assert_eq!(
            call(
                25,
                std::ptr::null_mut(),
                &request,
                &mut response,
                &mut buffer
            ),
            -2
        );
        assert!(response.object.is_null());
    }
}
