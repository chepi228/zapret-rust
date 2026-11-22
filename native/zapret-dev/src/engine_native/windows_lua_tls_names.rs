//! TLS names and identifiers from the pinned zapret library (MIT).
use super::*;

type Entry = (&'static CStr, u32, &'static [u8]);

fn publish_table(vm: Stack, name: &CStr, entries: &[Entry]) {
    let table = vm.table(entries.len() as c_int);
    for &(symbol, value, label) in entries {
        vm.integer(value as isize);
        vm.set(GLOBALS, symbol);
        vm.integer(value as isize);
        let key = vm.top();
        vm.bytes(label);
        vm.set_item(table, key, vm.top());
        vm.reset(table);
    }
    vm.set(GLOBALS, name);
}

pub(super) fn publish(vm: Stack) {
    publish_table(vm, c"TLS_HELLO_EXT_NAMES", TLS_HELLO_EXT_NAMES);
    publish_table(vm, c"TLS_RECORD_TYPE_NAMES", TLS_RECORD_TYPE_NAMES);
    publish_table(vm, c"TLS_HANDSHAKE_TYPE_NAMES", TLS_HANDSHAKE_TYPE_NAMES);
    publish_table(
        vm,
        c"TLS_HANDSHAKE_QUIC_TP_NAMES",
        TLS_HANDSHAKE_QUIC_TP_NAMES,
    );
    for (symbol, value) in [
        (c"TLS_VER_SSL30", 0x0300u32),
        (c"TLS_VER_TLS10", 0x0301u32),
        (c"TLS_VER_TLS11", 0x0302u32),
        (c"TLS_VER_TLS12", 0x0303u32),
        (c"TLS_VER_TLS13", 0x0304u32),
    ] {
        vm.integer(value as isize);
        vm.set(GLOBALS, symbol);
    }
}

const TLS_HELLO_EXT_NAMES: &[Entry] = &[
    (c"TLS_EXT_SERVER_NAME", 0, b"server_name"),
    (c"TLS_EXT_MAX_FRAGMENT_LENGTH", 1, b"max_fragment_length"),
    (
        c"TLS_EXT_CLIENT_CERTIFICATE_URL",
        2,
        b"client_certificate_url",
    ),
    (c"TLS_EXT_TRUSTED_CA_KEYS", 3, b"trusted_ca_keys"),
    (c"TLS_EXT_TRUNCATED_HMAC", 4, b"truncated_hmac"),
    (c"TLS_EXT_STATUS_REQUEST", 5, b"status_request"),
    (c"TLS_EXT_USER_MAPPING", 6, b"user_mapping"),
    (c"TLS_EXT_CLIENT_AUTHZ", 7, b"client_authz"),
    (c"TLS_EXT_SERVER_AUTHZ", 8, b"server_authz"),
    (c"TLS_EXT_CERT_TYPE", 9, b"cert_type"),
    (c"TLS_EXT_SUPPORTED_GROUPS", 10, b"supported_groups"),
    (c"TLS_EXT_EC_POINT_FORMATS", 11, b"ec_point_formats"),
    (c"TLS_EXT_SRP", 12, b"srp"),
    (c"TLS_EXT_SIGNATURE_ALGORITHMS", 13, b"signature_algorithms"),
    (c"TLS_EXT_USE_SRTP", 14, b"use_srtp"),
    (c"TLS_EXT_HEARTBEAT", 15, b"heartbeat"),
    (
        c"TLS_EXT_ALPN",
        16,
        b"application_layer_protocol_negotiation",
    ),
    (c"TLS_EXT_STATUS_REQUEST_V2", 17, b"status_request_v2"),
    (
        c"TLS_EXT_SIGNED_CERTIFICATE_TIMESTAMP",
        18,
        b"signed_certificate_timestamp",
    ),
    (c"TLS_EXT_CLIENT_CERT_TYPE", 19, b"client_certificate_type"),
    (c"TLS_EXT_SERVER_CERT_TYPE", 20, b"server_certificate_type"),
    (c"TLS_EXT_PADDING", 21, b"padding"),
    (c"TLS_EXT_ENCRYPT_THEN_MAC", 22, b"encrypt_then_mac"),
    (
        c"TLS_EXT_EXTENDED_MASTER_SECRET",
        23,
        b"extended_master_secret",
    ),
    (c"TLS_EXT_TOKEN_BINDING", 24, b"token_binding"),
    (c"TLS_EXT_CACHED_INFO", 25, b"cached_info"),
    (c"TLS_EXT_COMPRESS_CERTIFICATE", 27, b"compress_certificate"),
    (c"TLS_EXT_RECORD_SIZE_LIMIT", 28, b"record_size_limit"),
    (
        c"TLS_EXT_DELEGATED_CREDENTIALS",
        34,
        b"delegated_credentials",
    ),
    (c"TLS_EXT_SESSION_TICKET_TLS", 35, b"session_ticket"),
    (c"TLS_EXT_KEY_SHARE_OLD", 40, b"Reserved (key_share)"),
    (c"TLS_EXT_PRE_SHARED_KEY", 41, b"pre_shared_key"),
    (c"TLS_EXT_EARLY_DATA", 42, b"early_data"),
    (c"TLS_EXT_SUPPORTED_VERSIONS", 43, b"supported_versions"),
    (c"TLS_EXT_COOKIE", 44, b"cookie"),
    (
        c"TLS_EXT_PSK_KEY_EXCHANGE_MODES",
        45,
        b"psk_key_exchange_modes",
    ),
    (
        c"TLS_EXT_TICKET_EARLY_DATA_INFO",
        46,
        b"Reserved (ticket_early_data_info)",
    ),
    (
        c"TLS_EXT_CERTIFICATE_AUTHORITIES",
        47,
        b"certificate_authorities",
    ),
    (c"TLS_EXT_OID_FILTERS", 48, b"oid_filters"),
    (c"TLS_EXT_POST_HANDSHAKE_AUTH", 49, b"post_handshake_auth"),
    (
        c"TLS_EXT_SIGNATURE_ALGORITHMS_CERT",
        50,
        b"signature_algorithms_cert",
    ),
    (c"TLS_EXT_KEY_SHARE", 51, b"key_share"),
    (c"TLS_EXT_TRANSPARENCY_INFO", 52, b"transparency_info"),
    (
        c"TLS_EXT_CONNECTION_ID_DEPRECATED",
        53,
        b"connection_id (deprecated)",
    ),
    (c"TLS_EXT_CONNECTION_ID", 54, b"connection_id"),
    (c"TLS_EXT_EXTERNAL_ID_HASH", 55, b"external_id_hash"),
    (c"TLS_EXT_EXTERNAL_SESSION_ID", 56, b"external_session_id"),
    (
        c"TLS_EXT_QUIC_TRANSPORT_PARAMETERS_V1",
        57,
        b"quic_transport_parameters",
    ),
    (c"TLS_EXT_TICKET_REQUEST", 58, b"ticket_request"),
    (c"TLS_EXT_DNSSEC_CHAIN", 59, b"dnssec_chain"),
    (c"TLS_EXT_GREASE_0A0A", 2570, b"Reserved (GREASE)"),
    (c"TLS_EXT_GREASE_1A1A", 6682, b"Reserved (GREASE)"),
    (c"TLS_EXT_GREASE_2A2A", 10794, b"Reserved (GREASE)"),
    (c"TLS_EXT_NPN", 13172, b"next_protocol_negotiation"),
    (c"TLS_EXT_GREASE_3A3A", 14906, b"Reserved (GREASE)"),
    (c"TLS_EXT_ALPS_OLD", 17513, b"application_settings_old"),
    (c"TLS_EXT_ALPS", 17613, b"application_settings"),
    (c"TLS_EXT_GREASE_4A4A", 19018, b"Reserved (GREASE)"),
    (c"TLS_EXT_GREASE_5A5A", 23130, b"Reserved (GREASE)"),
    (c"TLS_EXT_GREASE_6A6A", 27242, b"Reserved (GREASE)"),
    (c"TLS_EXT_CHANNEL_ID_OLD", 30031, b"channel_id_old"),
    (c"TLS_EXT_CHANNEL_ID", 30032, b"channel_id"),
    (c"TLS_EXT_RENEGOTIATION_INFO", 65281, b"renegotiation_info"),
    (c"TLS_EXT_GREASE_7A7A", 31354, b"Reserved (GREASE)"),
    (c"TLS_EXT_GREASE_8A8A", 35466, b"Reserved (GREASE)"),
    (c"TLS_EXT_GREASE_9A9A", 39578, b"Reserved (GREASE)"),
    (c"TLS_EXT_GREASE_AAAA", 43690, b"Reserved (GREASE)"),
    (c"TLS_EXT_GREASE_BABA", 47802, b"Reserved (GREASE)"),
    (c"TLS_EXT_GREASE_CACA", 51914, b"Reserved (GREASE)"),
    (c"TLS_EXT_GREASE_DADA", 56026, b"Reserved (GREASE)"),
    (c"TLS_EXT_GREASE_EAEA", 60138, b"Reserved (GREASE)"),
    (c"TLS_EXT_GREASE_FAFA", 64250, b"Reserved (GREASE)"),
    (
        c"TLS_EXT_QUIC_TRANSPORT_PARAMETERS",
        65445,
        b"quic_transport_parameters (drafts version)",
    ),
    (
        c"TLS_EXT_ENCRYPTED_SERVER_NAME",
        65486,
        b"encrypted_server_name",
    ),
    (
        c"TLS_EXT_ENCRYPTED_CLIENT_HELLO",
        65037,
        b"encrypted_client_hello",
    ),
    (
        c"TLS_EXT_ECH_OUTER_EXTENSIONS",
        64768,
        b"ech_outer_extensions",
    ),
];

const TLS_RECORD_TYPE_NAMES: &[Entry] = &[
    (
        c"TLS_RECORD_TYPE_CHANGE_CIPHER_SPEC",
        0x14,
        b"change_cipher_spec",
    ),
    (c"TLS_RECORD_TYPE_ALERT", 0x15, b"alert"),
    (c"TLS_RECORD_TYPE_HANDSHAKE", 0x16, b"handshake"),
    (c"TLS_RECORD_TYPE_DATA", 0x17, b"data"),
    (c"TLS_RECORD_TYPE_HEARTBEAT", 0x18, b"heartbeat"),
];

const TLS_HANDSHAKE_TYPE_NAMES: &[Entry] = &[
    (c"TLS_HANDSHAKE_TYPE_HELLO_REQUEST", 0, b"hello_request"),
    (c"TLS_HANDSHAKE_TYPE_CLIENT", 1, b"client_hello"),
    (c"TLS_HANDSHAKE_TYPE_SERVER", 2, b"server_hello"),
    (c"TLS_HANDSHAKE_TYPE_CERTIFICATE", 11, b"certificate"),
    (c"TLS_HANDSHAKE_TYPE_KEY_EXCHANGE", 12, b"key_exchange"),
    (
        c"TLS_HANDSHAKE_TYPE_CERTIFICATE_REQUEST",
        13,
        b"certificate_request",
    ),
    (c"TLS_HANDSHAKE_TYPE_SERVER_HELLO_DONE", 14, b"hello_done"),
    (
        c"TLS_HANDSHAKE_TYPE_CERTIFICATE_VERIFY",
        15,
        b"certificate_verify",
    ),
    (
        c"TLS_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE",
        16,
        b"client_key_exchange",
    ),
    (c"TLS_HANDSHAKE_TYPE_FINISHED", 20, b"finished"),
    (
        c"TLS_HANDSHAKE_TYPE_CERTIFICATE_URL",
        21,
        b"certificate_url",
    ),
    (
        c"TLS_HANDSHAKE_TYPE_CERTIFICATE_STATUS",
        22,
        b"certificate_status",
    ),
    (
        c"TLS_HANDSHAKE_TYPE_SUPPLEMENTAL_DATA",
        23,
        b"supplemental_data",
    ),
    (c"TLS_HANDSHAKE_TYPE_KEY_UPDATE", 24, b"key_update"),
    (
        c"TLS_HANDSHAKE_TYPE_COMPRESSED_CERTIFICATE",
        25,
        b"compressed_certificate",
    ),
];

const TLS_HANDSHAKE_QUIC_TP_NAMES: &[Entry] = &[
    (
        c"TLS_HANDSHAKE_QUIC_TP_ORIGINAL_DESTINATION_CONNECTION_ID",
        0x00,
        b"original_destination_connection_id",
    ),
    (
        c"TLS_HANDSHAKE_QUIC_TP_MAX_IDLE_TIMEOUT",
        0x01,
        b"max_idle_timeout",
    ),
    (
        c"TLS_HANDSHAKE_QUIC_TP_STATELESS_RESET_TOKEN",
        0x02,
        b"stateless_reset_token",
    ),
    (
        c"TLS_HANDSHAKE_QUIC_TP_MAX_UDP_PAYLOAD_SIZE",
        0x03,
        b"max_udp_payload_size",
    ),
    (
        c"TLS_HANDSHAKE_QUIC_TP_INITIAL_MAX_DATA",
        0x04,
        b"initial_max_data",
    ),
    (
        c"TLS_HANDSHAKE_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL",
        0x05,
        b"initial_max_stream_data_bidi_local",
    ),
    (
        c"TLS_HANDSHAKE_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE",
        0x06,
        b"initial_max_stream_data_bidi_remote",
    ),
    (
        c"TLS_HANDSHAKE_QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI",
        0x07,
        b"initial_max_stream_data_uni",
    ),
    (
        c"TLS_HANDSHAKE_QUIC_TP_INITIAL_MAX_STREAMS_UNI",
        0x09,
        b"initial_max_streams_uni",
    ),
    (
        c"TLS_HANDSHAKE_QUIC_TP_INITIAL_MAX_STREAMS_BIDI",
        0x08,
        b"initial_max_streams_bidi",
    ),
    (
        c"TLS_HANDSHAKE_QUIC_TP_ACK_DELAY_EXPONENT",
        0x0a,
        b"ack_delay_exponent",
    ),
    (
        c"TLS_HANDSHAKE_QUIC_TP_MAX_ACK_DELAY",
        0x0b,
        b"max_ack_delay",
    ),
    (
        c"TLS_HANDSHAKE_QUIC_TP_DISABLE_ACTIVE_MIGRATION",
        0x0c,
        b"disable_active_migration",
    ),
    (
        c"TLS_HANDSHAKE_QUIC_TP_PREFERRED_ADDRESS",
        0x0d,
        b"preferred_address",
    ),
    (
        c"TLS_HANDSHAKE_QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT",
        0x0e,
        b"active_connection_id_limit",
    ),
    (
        c"TLS_HANDSHAKE_QUIC_TP_INITIAL_SOURCE_CONNECTION_ID",
        0x0f,
        b"initial_source_connection_id",
    ),
    (
        c"TLS_HANDSHAKE_QUIC_TP_RETRY_SOURCE_CONNECTION_ID",
        0x10,
        b"retry_source_connection_id",
    ),
    (
        c"TLS_HANDSHAKE_QUIC_TP_MAX_DATAGRAM_FRAME_SIZE",
        0x20,
        b"max_datagram_frame_size",
    ),
    (
        c"TLS_HANDSHAKE_QUIC_TP_CIBIR_ENCODING",
        0x1000,
        b"cibir_encoding",
    ),
    (c"TLS_HANDSHAKE_QUIC_TP_LOSS_BITS", 0x1057, b"loss_bits"),
    (
        c"TLS_HANDSHAKE_QUIC_TP_GREASE_QUIC_BIT",
        0x2ab2,
        b"grease_quic_bit",
    ),
    (
        c"TLS_HANDSHAKE_QUIC_TP_ENABLE_TIME_STAMP",
        0x7157,
        b"enable_time_stamp",
    ),
    (
        c"TLS_HANDSHAKE_QUIC_TP_ENABLE_TIME_STAMP_V2",
        0x7158,
        b"enable_time_stamp_v2",
    ),
    (
        c"TLS_HANDSHAKE_QUIC_TP_VERSION_INFORMATION",
        0x11,
        b"version_information",
    ),
    (
        c"TLS_HANDSHAKE_QUIC_TP_VERSION_INFORMATION_DRAFT",
        0xff73db,
        b"version_information_draft",
    ),
    (
        c"TLS_HANDSHAKE_QUIC_TP_MIN_ACK_DELAY_OLD",
        0xde1a,
        b"min_ack_delay",
    ),
    (
        c"TLS_HANDSHAKE_QUIC_TP_GOOGLE_USER_AGENT",
        0x3129,
        b"google_user_agent",
    ),
    (
        c"TLS_HANDSHAKE_QUIC_TP_GOOGLE_KEY_UPDATE_NOT_YET_SUPPORTED",
        0x312B,
        b"google_key_update_not_yet_supported",
    ),
    (
        c"TLS_HANDSHAKE_QUIC_TP_GOOGLE_QUIC_VERSION",
        0x4752,
        b"google_quic_version",
    ),
    (
        c"TLS_HANDSHAKE_QUIC_TP_GOOGLE_INITIAL_RTT",
        0x3127,
        b"google_initial_rtt",
    ),
    (
        c"TLS_HANDSHAKE_QUIC_TP_GOOGLE_SUPPORT_HANDSHAKE_DONE",
        0x312A,
        b"google_support_handshake_done",
    ),
    (
        c"TLS_HANDSHAKE_QUIC_TP_GOOGLE_QUIC_PARAMS",
        0x4751,
        b"google_quic_params",
    ),
    (
        c"TLS_HANDSHAKE_QUIC_TP_GOOGLE_CONNECTION_OPTIONS",
        0x3128,
        b"google_connection_options",
    ),
    (
        c"TLS_HANDSHAKE_QUIC_TP_FACEBOOK_PARTIAL_RELIABILITY",
        0xFF00,
        b"facebook_partial_reliability",
    ),
    (
        c"TLS_HANDSHAKE_QUIC_TP_ADDRESS_DISCOVERY",
        0x9f81a176,
        b"address_discovery",
    ),
    (
        c"TLS_HANDSHAKE_QUIC_TP_MIN_ACK_DELAY_DRAFT_V1",
        0xFF03DE1A,
        b"min_ack_delay (draft-01)",
    ),
    (
        c"TLS_HANDSHAKE_QUIC_TP_MIN_ACK_DELAY_DRAFT05",
        0xff04de1a,
        b"min_ack_delay (draft-05)",
    ),
    (
        c"TLS_HANDSHAKE_QUIC_TP_MIN_ACK_DELAY",
        0xff04de1b,
        b"min_ack_delay",
    ),
];
