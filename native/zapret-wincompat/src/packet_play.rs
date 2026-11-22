//! Prepare TCP and UDP packet data for profile discovery and Lua.
use crate::{
    auto_hostlist::zapret_is_retransmission,
    conntrack::Positions,
    logging::LogSink,
    play_prolog::{PlayState, connection},
    protocol::{bytes, http::HttpExtractHost, l7_payload_match, l7payload_str, probe, quic, tls},
    reassembly::session::{
        DeferredPacket, Ops as ReassemblyOps, Session, zapret_reassembly_append,
        zapret_reassembly_cancel, zapret_reassembly_defer, zapret_reassembly_start,
    },
};
use std::{
    ffi::{CStr, c_char},
    mem::MaybeUninit,
    ptr,
};

const TCP: u8 = 6;
const UDP: u8 = 17;
const SYN: u8 = 2;
const MAX_REASSEMBLY: usize = 16_384;
const HOST_CAPACITY: usize = 256;

#[repr(C)]
#[derive(Clone, Copy)]
struct Payload {
    data: *const u8,
    length: usize,
}

impl Payload {
    const EMPTY: Self = Self {
        data: ptr::null(),
        length: 0,
    };

    unsafe fn assembled(session: &Session) -> Self {
        let (data, length) = unsafe { session.payload() };
        Self { data, length }
    }

    // A span may refer to a reassembly buffer. Callers read it before a
    // lifecycle operation that can release the buffer.
    unsafe fn bytes(&self) -> &[u8] {
        unsafe { bytes(self.data, self.length) }
    }
}

#[repr(C)]
struct Input {
    interface_in: *const c_char,
    interface_out: *const c_char,
    payload_disable: u64,
    reassembly_disable: u64,
    mark: u32,
    desync_mark: u32,
    replay: bool,
    debug: bool,
}

#[repr(C)]
struct Ops {
    reassembly: *const ReassemblyOps,
    tcp_reply: unsafe extern "C" fn(*mut PlayState),
    tcp_retransmit: unsafe extern "C" fn(*mut PlayState, *const c_char),
    dns_response: unsafe extern "C" fn(*const u8, usize) -> bool,
    log: LogSink,
    tls_record: TlsDump,
    tls_handshake: TlsDump,
}

type TlsDump = unsafe extern "C" fn(*const u8, usize);

struct Play<'a> {
    state: *mut PlayState,
    input: &'a Input,
    ops: &'a Ops,
}

impl Play<'_> {
    unsafe fn original(&self) -> Payload {
        let packet = unsafe { (*self.state).packet };
        unsafe {
            Payload {
                data: (*packet).payload,
                length: (*packet).payload_length,
            }
        }
    }

    fn report(&self, message: &CStr) {
        if self.input.debug {
            unsafe { (self.ops.log)(message.as_ptr()) };
        }
    }

    unsafe fn dump_tls(&self, payload: Payload, dump: TlsDump) {
        if self.input.debug {
            unsafe { dump(payload.data, payload.length) };
        }
    }

    unsafe fn probe(&self, probes: &[probe::Probe], track: *mut std::ffi::c_void, data: Payload) {
        let debug = self.input.debug;
        let tracked = if track.is_null() {
            ptr::null_mut()
        } else {
            unsafe { ptr::addr_of_mut!((*connection(track)).l7) }
        };
        let matched = unsafe {
            probe::probe_payload(
                probes.as_ptr(),
                probes.len() as i32,
                data.data,
                data.length,
                tracked,
                ptr::addr_of_mut!((*self.state).l7),
                ptr::addr_of_mut!((*self.state).payload_kind),
                self.input.payload_disable,
            )
        };
        if matched && debug {
            unsafe {
                (self.ops.log)(
                    c"packet contains %s payload\n".as_ptr(),
                    l7payload_str((*self.state).payload_kind),
                )
            };
        }
    }

    unsafe fn cancel(&self, session: Option<&Session>) {
        if let Some(session) = session {
            unsafe { zapret_reassembly_cancel(session, &*self.ops.reassembly) };
        }
    }

    unsafe fn defer(&self, session: &Session, complete: bool) -> bool {
        let packet = unsafe { (*self.state).packet };
        let input = unsafe {
            DeferredPacket {
                destination: ptr::addr_of!((*self.state).destination).cast(),
                interface_in: self.input.interface_in,
                interface_out: self.input.interface_out,
                data: (*packet).data,
                length: (*packet).length,
                payload_length: (*packet).payload_length,
                original_mark: self.input.mark,
                mark: self.input.mark | self.input.desync_mark,
            }
        };
        unsafe { zapret_reassembly_defer(session, &*self.ops.reassembly, &input, complete) }
    }

    unsafe fn start(
        &self,
        session: &Session,
        protocol: u8,
        kind: u32,
        size: usize,
        payload: Payload,
    ) -> bool {
        unsafe {
            zapret_reassembly_start(
                session,
                &*self.ops.reassembly,
                protocol,
                kind,
                size,
                MAX_REASSEMBLY,
                payload.data,
                payload.length,
            )
        }
    }

    unsafe fn append(&self, session: &Session, protocol: u8, payload: Payload) -> bool {
        unsafe {
            zapret_reassembly_append(
                session,
                &*self.ops.reassembly,
                protocol,
                payload.data,
                payload.length,
            )
        }
    }

    unsafe fn tcp_payload(&self, original: Payload, output: &mut Payload) -> bool {
        let state = self.state;
        let session = unsafe { Session::for_track((*state).track) };
        let replay = unsafe { Session::for_track((*state).replay_track) };
        let data = if self.input.replay {
            match replay.as_ref() {
                Some(session) if unsafe { session.active() } => unsafe {
                    Payload::assembled(session)
                },
                _ => original,
            }
        } else {
            match session.as_ref() {
                Some(session) if unsafe { self.append(session, TCP, original) } => unsafe {
                    Payload::assembled(session)
                },
                _ => original,
            }
        };
        *output = data;
        unsafe { (self.ops.tcp_retransmit)(state, self.input.interface_in) };

        let assembly_active = replay
            .as_ref()
            .is_some_and(|session| unsafe { session.active() });
        if !assembly_active {
            unsafe { self.probe(probe::TCP_CLIENT, (*state).replay_track, data) };
            let pos = unsafe { (*state).positions.cast::<Positions>() };
            if !pos.is_null()
                && unsafe { (*state).payload_kind } == probe::UNKNOWN
                && unsafe {
                    (*pos)
                        .client
                        .sequence
                        .wrapping_sub((*pos).client.initial_sequence)
                } == 1
            {
                unsafe { self.probe(probe::TCP_FIRST, (*state).replay_track, data) };
            }
        }
        let tls_assembly = assembly_active
            && replay
                .as_ref()
                .is_some_and(|session| unsafe { session.kind() } == probe::TLS_CLIENT_HELLO);
        if unsafe { (*state).payload_kind } == probe::TLS_CLIENT_HELLO || tls_assembly {
            unsafe { (*state).payload_kind = probe::TLS_CLIENT_HELLO };
            let complete = tls::record_full(unsafe { data.bytes() });
            if complete {
                unsafe {
                    self.report(c"TLS client hello is FULL\n");
                    self.dump_tls(data, self.ops.tls_record);
                }
            } else {
                self.report(c"TLS client hello is PARTIAL\n");
            }
            if let Some(session) = session.as_ref().filter(|_| {
                !l7_payload_match(probe::TLS_CLIENT_HELLO, self.input.reassembly_disable)
            }) {
                if !complete
                    && !unsafe { session.active() }
                    && !unsafe {
                        zapret_is_retransmission(ptr::addr_of!((*session.positions()).client))
                    }
                {
                    let Some(size) = tls::record_length(unsafe { original.bytes() }) else {
                        return false;
                    };
                    if !unsafe { self.start(session, TCP, probe::TLS_CLIENT_HELLO, size, original) }
                    {
                        return false;
                    }
                }
                if unsafe { session.active() } {
                    if unsafe { self.defer(session, session.full()) } {
                        return true;
                    }
                    // A failed enqueue released the assembled bytes.
                    *output = original;
                    unsafe { (*state).payload_kind = probe::UNKNOWN };
                    return false;
                }
            }
            unsafe {
                (*state).have_host = tls::TLSHelloExtractHost(
                    data.data,
                    data.length,
                    ptr::addr_of_mut!((*state).host).cast(),
                    HOST_CAPACITY,
                    true,
                );
            }
        } else {
            if let Some(session) = session.as_ref() {
                unsafe { self.cancel(Some(session)) };
                *output = original;
            }
            if unsafe { (*state).payload_kind } == probe::HTTP_REQUEST {
                unsafe {
                    (*state).have_host = HttpExtractHost(
                        output.data,
                        output.length,
                        ptr::addr_of_mut!((*state).host).cast(),
                        HOST_CAPACITY,
                    );
                }
            }
        }
        false
    }

    unsafe fn quic_payload(&self, buffer: &mut [MaybeUninit<u8>], output: &mut Payload) -> bool {
        let session = unsafe { Session::for_track((*self.state).track) };
        let allowed = session
            .as_ref()
            .filter(|_| !l7_payload_match(probe::QUIC_INITIAL, self.input.reassembly_disable));
        let original = unsafe { self.original() };
        let mut clear = [MaybeUninit::uninit(); MAX_REASSEMBLY];
        let decoded = if self.input.replay {
            unsafe { Session::for_track((*self.state).replay_track) }
                .filter(|replay| unsafe { replay.active() })
                .map(|replay| unsafe { Payload::assembled(&replay) })
        } else {
            quic::decrypt(unsafe { original.bytes() }, &mut clear, MAX_REASSEMBLY).map(|length| {
                Payload {
                    data: clear.as_ptr().cast(),
                    length,
                }
            })
        };
        let Some(decoded) = decoded else {
            unsafe {
                self.cancel(session.as_ref());
                self.report(c"QUIC initial decryption failed\n");
            }
            return false;
        };
        let data = if let Some(active) = allowed.filter(|session| unsafe { session.active() }) {
            if !unsafe { self.append(active, UDP, decoded) } {
                return false;
            }
            unsafe { Payload::assembled(active) }
        } else {
            decoded
        };
        let Some((length, covered)) = quic::defragment(unsafe { data.bytes() }, buffer) else {
            unsafe {
                self.cancel(session.as_ref());
                self.report(c"QUIC initial defrag CRYPTO failed\n");
            }
            return false;
        };
        let mut hello_offset = 0;
        let mut hello_length = 0;
        let mut hello = Payload::EMPTY;
        let mut complete = false;
        if covered {
            let data = buffer.as_ptr().cast::<u8>();
            self.report(c"QUIC initial contains CRYPTO with full fragment coverage\n");
            if unsafe {
                quic::IsQUICCryptoHello(data, length, &mut hello_offset, &mut hello_length)
            } {
                hello = Payload {
                    data: unsafe { data.add(hello_offset) },
                    length: hello_length,
                };
                complete = tls::handshake_full(unsafe { hello.bytes() });
                if complete {
                    unsafe {
                        self.report(c"packet contains full TLS ClientHello\n");
                        self.dump_tls(hello, self.ops.tls_handshake);
                    }
                } else {
                    self.report(c"packet contains partial TLS ClientHello\n");
                }
            } else {
                self.report(c"packet does not contain TLS ClientHello\n");
            }
        } else {
            self.report(c"QUIC initial contains CRYPTO with partial fragment coverage\n");
        }
        if let Some(session) = allowed {
            if !unsafe { session.active() }
                && !complete
                && (!covered || !hello.data.is_null())
                && !unsafe {
                    self.start(session, UDP, probe::QUIC_INITIAL, MAX_REASSEMBLY, decoded)
                }
            {
                unsafe { self.cancel(Some(session)) };
                return false;
            }
            if unsafe { session.active() } {
                return unsafe { self.defer(session, complete) };
            }
        }
        if !hello.data.is_null() {
            unsafe {
                (*self.state).have_host = tls::TLSHelloExtractHostFromHandshake(
                    hello.data,
                    hello.length,
                    ptr::addr_of_mut!((*self.state).host).cast(),
                    HOST_CAPACITY,
                    true,
                );
            }
            *output = hello;
            unsafe { self.cancel(session.as_ref()) };
        } else {
            unsafe { self.cancel(session.as_ref()) };
            self.report(if covered {
                c"QUIC initial without ClientHello\n"
            } else {
                c"QUIC initial fragmented CRYPTO\n"
            });
        }
        false
    }
}

// True means ownership of the original packet has passed to the deferred
// queue. The C caller can return a drop verdict without running Lua again.
#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn zapret_prepare_tcp(
    state: *mut PlayState,
    input: &Input,
    ops: &Ops,
    output: &mut Payload,
) -> bool {
    let play = Play { state, input, ops };
    let original = unsafe { play.original() };
    *output = original;
    // A dissected TCP header contains the flags byte at offset 13.
    let tcp = unsafe { (*(*state).packet).tcp };
    let has_data = original.length != 0 && unsafe { tcp.add(13).read() } & SYN == 0;
    if unsafe { (*state).reverse } {
        if has_data {
            unsafe { play.probe(probe::TCP_SERVER, (*state).track, original) };
            if unsafe { (*state).payload_kind } == probe::TLS_SERVER_HELLO {
                unsafe { play.dump_tls(original, ops.tls_record) };
            }
        }
        unsafe { (ops.tcp_reply)(state) };
        false
    } else {
        has_data && unsafe { play.tcp_payload(original, output) }
    }
}

// True selects the QUIC path, which is the only UDP path that needs scratch.
#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn zapret_prepare_udp(
    state: *mut PlayState,
    input: &Input,
    ops: &Ops,
) -> bool {
    let play = Play { state, input, ops };
    let original = unsafe { play.original() };
    let track = unsafe { (*state).track };
    if original.length != 0 {
        unsafe { play.probe(probe::UDP, track, original) };
        match unsafe { (*state).payload_kind } {
            probe::QUIC_INITIAL if !unsafe { (*state).reverse } => return true,
            probe::DNS_RESPONSE => {
                unsafe { (ops.dns_response)(original.data, original.length) };
            }
            _ => {}
        }
    }
    unsafe { play.cancel(Session::for_track(track).as_ref()) };
    false
}

#[unsafe(no_mangle)]
unsafe extern "C-unwind" fn zapret_prepare_quic(
    state: *mut PlayState,
    input: &Input,
    ops: &Ops,
    buffer: &mut [MaybeUninit<u8>; MAX_REASSEMBLY],
    output: &mut Payload,
) -> bool {
    *output = Payload::EMPTY;
    unsafe { Play { state, input, ops }.quic_payload(buffer, output) }
}
