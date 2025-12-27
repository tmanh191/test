/*  DISCLAIMER
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE. */

// SPDX-License-Identifier: GPL-2.0+
#define BPF_LICENSE GPL

#include "bpf.h"
#include <uapi/asm/fcntl.h>
#include <uapi/linux/ptrace.h>

#ifndef true
#define true 1
#endif
#ifndef false
#define false 0
#endif

// config data from userspace
BPF_ARRAY(config, config_t, 1);

// event patterns from userspace
BPF_ARRAY(patterns, event_pattern_t, MAX_PATTERNS);

// threshold patterns from userspace
BPF_ARRAY(threshold_patterns, threshold_pattern_t, MAX_THRESHOLD_PATTERNS);

// hash map (pid -> pidstat) to analyze file access pattern per pid and flag suspicious pid
BPF_HASH(pidstats, u32 /* pid */, pidstat_t, 1024);

// ring buffer to report events (16 pages x 4096 bytes shared across all CPUs)
// getconf PAGESIZE returns the page size in bytes (4096)
BPF_RINGBUF_OUTPUT(events, 1 << 4);


// get config from BPF_ARRAY
static __always_inline config_t *get_config() {
    int zero = 0;
    return config.lookup(&zero);
}

// get pid stats from BPF_HASH
static __always_inline pidstat_t *get_stats(u32 *pid) {
    pidstat_t zero;
    __builtin_memset(&zero, 0, sizeof(zero));
    zero.event_bitmap = BITMAP_INIT;
    return pidstats.lookup_or_try_init(pid, &zero);
}

// update pid stats (but does not save)
static __always_inline void update_stats(config_t *conf, event_type_t type, const pidstat_t *curr, pidstat_t *updated) {
    __builtin_memcpy(updated, curr, sizeof(*updated));

    time_t now = bpf_ktime_get_ns();
    time_t time_since_reset = now - curr->last_reset_ts;
    if (conf && curr->last_reset_ts && (time_since_reset > conf->reset_period_ns)) {
        // reset counters
        __builtin_memset(updated->event_counts, 0, sizeof(counts_t) * EVENT_TYPES);
        updated->last_reset_ts = now;
    }
    // this doesn't work: updated->event_counts[type]++; - maybe try with bpf_probe_kernel_read?
    switch (type) {
        case T_OPEN:
            updated->event_counts[0]++;
            break;
        case T_CREATE:
            updated->event_counts[1]++;
            break;
        case T_DELETE:
            updated->event_counts[2]++;
            break;
        case T_ENCRYPT:
            updated->event_counts[3]++;
            break;
        case T_READ:
            updated->event_counts[4]++;
            break;
        case T_WRITE:
            updated->event_counts[5]++;
            break;
        case T_SCAN:
            updated->event_counts[6]++;
            break;
        case T_RENAME:
            updated->event_counts[7]++;
            break;
        case T_NET_SOCKET:
            updated->event_counts[8]++;
            break;
        case T_NET_CONNECT:
            updated->event_counts[9]++;
            break;
        default:
            break;
    }
    // shift and add the event_type
    updated->event_bitmap = (curr->event_bitmap << BITS_PER_EVENT) | (bitmap_t)type;
}

// Helper function: Check if pattern matches bitmap (general logic for all patterns)
// Returns 1 if pattern matches, 0 otherwise
// This function handles both exact match and subsequence match for patterns ending with DELETE
static __always_inline u8 check_pattern_match(bitmap_t bitmap, event_pattern_t *pat) {
    if (!pat || !pat->bitmask) return 0;
    
    // Try exact match first (fast path)
    if ((bitmap & pat->bitmask) == pat->bitmap) {
        return 1;
    }
    
    // Extract pattern events (from right to left, LSB to MSB)
    // Pattern [OPEN, CREATE, ENCRYPT, DELETE] becomes [DELETE, ENCRYPT, CREATE, OPEN]
    u8 pattern_len = 0;
    bitmap_t temp_mask = pat->bitmask;
    bitmap_t temp_bitmap = pat->bitmap;
    bitmap_t pattern_events[8] = {0};
    
    while (temp_mask != 0 && pattern_len < 8) {
        pattern_events[pattern_len] = temp_bitmap & EVENT_MASK;
        temp_bitmap >>= BITS_PER_EVENT;
        temp_mask >>= BITS_PER_EVENT;
        pattern_len++;
    }
    
    if (pattern_len == 0) return 0;
    
    bitmap_t last_event = bitmap & EVENT_MASK;
    
    // If pattern ends with DELETE, only match when DELETE actually occurs
    // This prevents false positives and reduces unnecessary MAJOR flags
    if (pattern_events[0] == T_DELETE) {
        // Only match when bitmap also ends with DELETE (actual pattern completion)
        if (last_event == T_DELETE) {
            // Find pattern events (except DELETE) in bitmap before DELETE
            u8 pattern_idx = 1; // Start from second event (skip DELETE at position 0)
            u8 bitmap_pos = 1;  // Start checking from position 1 (position 0 is DELETE)
            
            while (pattern_idx < pattern_len && bitmap_pos < BITMAP_EVENTS) {
                bitmap_t event_at_pos = (bitmap >> (bitmap_pos * BITS_PER_EVENT)) & EVENT_MASK;
                if (event_at_pos == 0xF) break; // Reached end of valid events
                
                if (event_at_pos == pattern_events[pattern_idx]) {
                    pattern_idx++; // Found this pattern event, move to next
                }
                bitmap_pos++; // Always move forward in bitmap
            }
            
            return (pattern_idx >= pattern_len) ? 1 : 0;
        }
        // Don't do predictive matching - only match when DELETE occurs
        return 0;
    }
    
    // Pattern doesn't end with DELETE, only exact match works
    return 0;
}

// Helper function: Check if threshold pattern matches thresholds_crossed bitmap
static __always_inline u8 check_threshold_pattern_match_inline(u16 thresholds, threshold_pattern_t *tpat) {
    if (!tpat || !tpat->bitmask) return 0;
    // Exact match: (thresholds & bitmask) == bitmap
    return ((thresholds & tpat->bitmask) == tpat->bitmap) ? 1 : 0;
}

// analyse pid stats and compute flags
static __always_inline void analyze_stats(config_t *conf, pidstat_t* stats, event_flags_t *flags) {
    __builtin_memset(flags, 0, sizeof(event_flags_t));

    // check counters and build thresholds_crossed bitmap
    u16 thresholds = 0;
    if (conf) {
        if (stats->event_counts[0] > conf->thresholds[0]) thresholds |= (1 << 0);
        if (stats->event_counts[1] > conf->thresholds[1]) thresholds |= (1 << 1);
        if (stats->event_counts[2] > conf->thresholds[2]) thresholds |= (1 << 2);
        if (stats->event_counts[3] > conf->thresholds[3]) thresholds |= (1 << 3);
        if (stats->event_counts[4] > conf->thresholds[4]) thresholds |= (1 << 4);
        if (stats->event_counts[5] > conf->thresholds[5]) thresholds |= (1 << 5);
        if (stats->event_counts[6] > conf->thresholds[6]) thresholds |= (1 << 6);
        if (stats->event_counts[7] > conf->thresholds[7]) thresholds |= (1 << 7);
        if (stats->event_counts[8] > conf->thresholds[8]) thresholds |= (1 << 8);
        if (stats->event_counts[9] > conf->thresholds[9]) thresholds |= (1 << 9);
    }
    flags->thresholds_crossed = thresholds;
    if (thresholds != 0) flags->severity = S_MINOR;

    // check pattern matches - loop through all patterns
    u8 pattern_found = 0;
    for (u8 i=0; i < MAX_PATTERNS; i++) {
        int k = i;
        event_pattern_t *pat = patterns.lookup(&k);
        if (pat && pat->bitmask) {
            if (check_pattern_match(stats->event_bitmap, pat)) {
                flags->pattern_id = i + 1;
                flags->severity = S_MAJOR;
                stats->pattern_counts++;
                // reset the bitmap only if pattern ends with DELETE and bitmap also ends with DELETE
                bitmap_t last_event = stats->event_bitmap & EVENT_MASK;
                if (last_event == T_DELETE) {
                    stats->event_bitmap = BITMAP_INIT;
                }
                pattern_found = 1;
                break;
            }
        }
    }
    
    // check threshold pattern matches - can match even if pattern matched
    if (thresholds != 0) {
        for (u8 i=0; i < MAX_THRESHOLD_PATTERNS; i++) {
            int k = i;
            threshold_pattern_t *tpat = threshold_patterns.lookup(&k);
            if (check_threshold_pattern_match_inline(thresholds, tpat)) {
                flags->threshold_pattern_id = i + 1;  // V1=1, V2=2, ...
                flags->severity = S_MAJOR;  // Override to MAJOR
                return;  // Early exit on threshold pattern match
            }
        }
    }
    
    // If pattern matched but no threshold pattern, return early
    if (pattern_found) {
        return;
    }
}

// submit event for userspace via ring buffer
static __always_inline int submit_event(void *ctx, u32 pid, event_type_t type, event_flags_t flags, const char *filename, bitmap_t bitmap) {
    event_t *event = events.ringbuf_reserve(sizeof(event_t));
    if (!event) {
        return 1;
    }
    
    event->ts = bpf_ktime_get_ns();
    event->pid = pid;
    event->type = type;
    event->flags = flags;
    event->event_bitmap = bitmap;  // Bitmap of last 8 events for display

    bpf_get_current_comm(&event->comm, TASK_COMM_LEN);

    if (filename) {
        int ret = bpf_probe_read_user_str(event->filename, FILENAME_SIZE, filename);
        if (ret < 0) {
            bpf_probe_read_kernel_str(event->filename, FILENAME_SIZE, filename);
        }
    } else {
        event->filename[0] = '\0';
    }

    events.ringbuf_submit(event, 0 /* flags */);
    return 0;
}

// update stats, analyse and submit event
static __always_inline int update_and_submit(void *ctx, event_type_t type, const char* filename, int emit_always) {
    u32 pid = bpf_get_current_pid_tgid();

    // get config
    config_t *conf = get_config();

    // get stats from BPF_HASH
    pidstat_t *curr = get_stats(&pid);
    if (!curr) {
        // cleanup old pid entries in pidstats?
        return 0;
    }

    // update stats
    pidstat_t updated;
    update_stats(conf, type, curr, &updated);

    // analyse stats
    event_flags_t flags;
    analyze_stats(conf, &updated, &flags);

    // save stats in BPF_HASH
    pidstats.update(&pid, &updated);

    // Submit ALL events to userspace (filtering is done in Python)
    // This matches the original perf buffer behavior
    // Pass updated bitmap for display
    return submit_event(ctx, pid, type, flags, filename, updated.event_bitmap);
}

// sys_open and sys_openat both have args->filename
TRACEPOINT_PROBE(syscalls, sys_enter_open) {
    // args from /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/format
    event_type_t type = T_OPEN;
    if (args->flags & O_CREAT) {
        type = T_CREATE;
    }
    return update_and_submit(args, type, args->filename, true);
}

// sys_open and sys_openat both have args->filename
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    // args from /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/format
    event_type_t type = T_OPEN;
    if (args->flags & O_CREAT) {
        type = T_CREATE;
    }
    return update_and_submit(args, type, args->filename, true);
}

// sys_unlink and sys_unlinkat both have args->pathname
TRACEPOINT_PROBE(syscalls, sys_enter_unlink) {
    // args from /sys/kernel/debug/tracing/events/syscalls/sys_enter_unlink/format
    return update_and_submit(args, T_DELETE, args->pathname, true);
}

// sys_unlink and sys_unlinkat both have args->pathname
TRACEPOINT_PROBE(syscalls, sys_enter_unlinkat) {
    // args from /sys/kernel/debug/tracing/events/syscalls/sys_enter_unlink/format
    return update_and_submit(args, T_DELETE, args->pathname, true);
}

// uprobe on openssl - High-level encryption functions
// int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
//                        ENGINE *impl, const unsigned char *key, const unsigned char *iv);
// int EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
//                       ENGINE *impl, const unsigned char *key, const unsigned char *iv, int enc);
int trace_encrypt1(struct pt_regs *ctx) {
    const char func[FILENAME_SIZE] = "EVP_EncryptInit_ex";
    return update_and_submit(ctx, T_ENCRYPT, func, true);
}
// int EVP_SealInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
//                  unsigned char **ek, int *ekl, unsigned char *iv,
//                  EVP_PKEY **pubk, int npubk);
int trace_encrypt2(struct pt_regs *ctx) {
    const char func[FILENAME_SIZE] = "EVP_SealInit";
    return update_and_submit(ctx, T_ENCRYPT, func, true);
}
// int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
//                       const unsigned char *in, int inl);
int trace_encrypt_update(struct pt_regs *ctx) {
    const char func[FILENAME_SIZE] = "EVP_EncryptUpdate";
    return update_and_submit(ctx, T_ENCRYPT, func, false);
}
// int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);
int trace_encrypt_final(struct pt_regs *ctx) {
    const char func[FILENAME_SIZE] = "EVP_EncryptFinal_ex";
    return update_and_submit(ctx, T_ENCRYPT, func, true);
}
// int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl);
// Used for key derivation in some ransomware
int trace_digest_init(struct pt_regs *ctx) {
    const char func[FILENAME_SIZE] = "EVP_DigestInit_ex";
    return update_and_submit(ctx, T_ENCRYPT, func, true);
}
// Low-level AES functions
// void AES_encrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key);
int trace_aes_encrypt(struct pt_regs *ctx) {
    const char func[FILENAME_SIZE] = "AES_encrypt";
    return update_and_submit(ctx, T_ENCRYPT, func, true);
}
// void AES_cbc_encrypt(const unsigned char *in, unsigned char *out,
//                      size_t length, const AES_KEY *key, unsigned char *ivec, const int enc);
int trace_aes_cbc_encrypt(struct pt_regs *ctx) {
    const char func[FILENAME_SIZE] = "AES_cbc_encrypt";
    return update_and_submit(ctx, T_ENCRYPT, func, true);
}
// void AES_ctr128_encrypt(const unsigned char *in, unsigned char *out,
//                         size_t length, const AES_KEY *key, unsigned char ivec[16],
//                         unsigned char ecount_buf[16], unsigned int *num);
int trace_aes_ctr_encrypt(struct pt_regs *ctx) {
    const char func[FILENAME_SIZE] = "AES_ctr128_encrypt";
    return update_and_submit(ctx, T_ENCRYPT, func, true);
}
// uprobe on libgcrypt
// gcry_error_t gcry_cipher_encrypt(gcry_cipher_hd_t h, unsigned char *out,
//                                  size_t outsize, const unsigned char *in, size_t inlen);
int trace_gcry_cipher_encrypt(struct pt_regs *ctx) {
    const char func[FILENAME_SIZE] = "gcry_cipher_encrypt";
    return update_and_submit(ctx, T_ENCRYPT, func, true);
}
// gcry_error_t gcry_cipher_setkey(gcry_cipher_hd_t h, const void *k, size_t l);
int trace_gcry_cipher_setkey(struct pt_regs *ctx) {
    const char func[FILENAME_SIZE] = "gcry_cipher_setkey";
    return update_and_submit(ctx, T_ENCRYPT, func, true);
}

TRACEPOINT_PROBE(syscalls, sys_enter_read) {
    const char func[FILENAME_SIZE] = "sys_read";
    return update_and_submit(args, T_READ, func, false);
}

TRACEPOINT_PROBE(syscalls, sys_enter_write) {
    const char func[FILENAME_SIZE] = "sys_write";
    return update_and_submit(args, T_WRITE, func, false);
}

TRACEPOINT_PROBE(syscalls, sys_enter_getdents64) {
    const char func[FILENAME_SIZE] = "sys_getdents64";
    return update_and_submit(args, T_SCAN, func, true);
}

TRACEPOINT_PROBE(syscalls, sys_enter_rename) {
    return update_and_submit(args, T_RENAME, args->newname, true);
}

TRACEPOINT_PROBE(syscalls, sys_enter_renameat) {
    return update_and_submit(args, T_RENAME, args->newname, true);
}

TRACEPOINT_PROBE(syscalls, sys_enter_renameat2) {
    return update_and_submit(args, T_RENAME, args->newname, true);
}

TRACEPOINT_PROBE(syscalls, sys_enter_socket) {
    const char func[FILENAME_SIZE] = "sys_socket";
    return update_and_submit(args, T_NET_SOCKET, func, true);
}

TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    const char func[FILENAME_SIZE] = "sys_connect";
    return update_and_submit(args, T_NET_CONNECT, func, true);
}
