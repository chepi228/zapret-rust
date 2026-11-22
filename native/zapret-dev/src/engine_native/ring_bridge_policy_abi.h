/* MIT. Resource-free bridge plans; the versioned backend API is unchanged. */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
typedef struct {
    uint32_t phase,operation;int32_t arguments,index;uint32_t output_index,object_class,constructor_class;
    int32_t return_count;size_t capacity;
} zapret_ring_entry_flow;
typedef struct {
    uint32_t operation;int32_t arguments,kind,backend;double number;size_t offset,length;
    uint32_t results;bool available;
} zapret_ring_entry_feedback;
typedef struct {uint32_t phase,object,operation;} zapret_ring_registration_flow;
typedef struct {int64_t integer;char name[64];size_t name_length;} zapret_ring_registration_view;
_Static_assert(sizeof(zapret_ring_entry_flow)==40 && sizeof(zapret_ring_entry_feedback)==48 &&
    sizeof(zapret_ring_registration_flow)==12 && sizeof(zapret_ring_registration_view)==80 &&
    offsetof(zapret_ring_registration_view, name_length)==72 &&
    sizeof(rr_request)==400 && offsetof(rr_request, present)==128 &&
    offsetof(rr_request, strings)==136 && offsetof(rr_request, lengths)==264 &&
    offsetof(rr_request, text_present)==392,
    "Rust ring bridge policy ABI");
uint32_t zapret_ring_entry_step(zapret_ring_entry_flow *,const zapret_ring_entry_feedback *);
const char *zapret_ring_entry_error(uint32_t);
const char *zapret_ring_loader_error_text(void);
void zapret_ring_request_number(rr_request *,int32_t,double);
void zapret_ring_request_text(rr_request *,int32_t,const uint8_t *,size_t);
void zapret_ring_request_store(rr_request *,void *);
void zapret_ring_release_object(void **,bool (*)(void *));
const char *zapret_ring_class_name(uint32_t);
uint32_t zapret_ring_registration_step(zapret_ring_registration_flow *,zapret_ring_registration_view *);
