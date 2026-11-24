//! Windows support shared with the pinned native C engine.
#[cfg(windows)]
mod address;
#[cfg(windows)]
mod address_prefix;
mod allocate;
mod auto_hostlist;
#[cfg(windows)]
mod blob;
#[cfg(windows)]
mod cache_lifecycle;
mod caches;
#[cfg(windows)]
mod capture_packet_policy;
mod checksum;
mod cli;
#[cfg(windows)]
mod cli_capture_options;
#[cfg(windows)]
mod cli_control;
#[cfg(windows)]
mod cli_list_options;
#[cfg(windows)]
mod cli_profile_filters;
#[cfg(windows)]
mod cli_startup_options;
mod collections;
mod compression;
mod config_lists;
mod conntrack;
#[cfg(windows)]
mod conntrack_lifecycle;
#[cfg(windows)]
mod console;
#[cfg(windows)]
mod desync_policy;
mod dns_response;
#[cfg(windows)]
mod engine_bootstrap;
mod engine_config;
#[cfg(windows)]
mod engine_entry;
#[cfg(windows)]
mod engine_fuzz;
#[cfg(windows)]
mod engine_lifecycle;
mod engine_loop;
#[cfg(windows)]
mod engine_prefix;
#[cfg(windows)]
mod file_helpers;
#[cfg(windows)]
mod file_policy;
#[cfg(windows)]
mod files;
mod filter_collections;
mod filters;
mod helpers;
mod host_pool;
mod ip_pool;
#[cfg(windows)]
mod list_lifecycle;
mod list_registry;
mod lists;
mod logging;
mod lua_aes;
mod lua_arguments;
#[cfg(windows)]
mod lua_aux;
#[cfg(windows)]
mod lua_buffer;
#[cfg(windows)]
mod lua_codec;
mod lua_conntrack_view;
#[cfg(windows)]
mod lua_context;
#[cfg(windows)]
mod lua_crypto;
#[cfg(windows)]
mod lua_file;
mod lua_gcm;
mod lua_hash;
#[cfg(windows)]
mod lua_header_entry;
#[cfg(windows)]
mod lua_instance;
#[cfg(windows)]
mod lua_interfaces;
#[cfg(windows)]
mod lua_invocation;
mod lua_numeric;
#[cfg(windows)]
mod lua_packet_arguments;
#[cfg(windows)]
mod lua_packet_assembly;
#[cfg(windows)]
mod lua_packet_dispatch;
#[cfg(windows)]
mod lua_packet_dissection;
#[cfg(windows)]
mod lua_packet_options;
#[cfg(windows)]
mod lua_registry;
mod lua_rules;
#[cfg(windows)]
mod lua_scalar;
#[cfg(windows)]
mod lua_startup;
#[cfg(windows)]
mod lua_system_tables;
#[cfg(windows)]
mod lua_table_policy;
#[cfg(windows)]
mod lua_vm;
#[cfg(windows)]
mod lua_zstream;
#[cfg(windows)]
mod native_cli_catalog;
#[cfg(windows)]
mod native_diagnostic_views;
#[cfg(windows)]
mod native_help_entry;
#[cfg(windows)]
mod native_logging_entry;
#[cfg(windows)]
mod network_environment;
mod network_gate;
mod packet;
mod packet_cache;
mod packet_play;
mod packet_policy;
mod packet_queue;
mod packet_route;
mod packet_write;
mod play_prolog;
#[cfg(windows)]
mod process;
mod profile_config;
mod profile_rediscovery;
mod profile_selection;
mod protocol;
mod reassembly;
#[cfg(windows)]
mod ring_bridge_policy;
#[cfg(windows)]
mod ring_loader;
#[cfg(windows)]
mod route_source;
#[cfg(windows)]
mod security_label;
#[cfg(windows)]
mod security_sandbox;
#[cfg(windows)]
mod security_token;
#[cfg(windows)]
mod service;
#[cfg(windows)]
mod startup_io;
#[cfg(windows)]
mod stdio;
mod system;
#[cfg(windows)]
mod system_diagnostics;
#[cfg(windows)]
mod text_buffer;
#[cfg(windows)]
mod timer_lifecycle;
mod timers;
#[cfg(windows)]
mod tls_debug_policy;
mod trial_startup;
#[cfg(windows)]
mod windivert;
mod windivert_filter;
mod wordexp;
#[cfg(windows)]
mod writable;

pub use system::*;
pub use wordexp::zapret_wordexp;
