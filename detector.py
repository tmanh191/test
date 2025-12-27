#!/usr/bin/python3

#   DISCLAIMER
#   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#   SOFTWARE.

import os
import sys
import time
import ctypes
from bcc import BPF
import csv
import signal

# bitmap encoding details (keep in sync with <bpf.h>)
BITS_PER_EVENT = 4
EVENT_MASK = (1 << BITS_PER_EVENT) - 1
BITMAP_EVENTS = 8  # max number of events in bitmap

class EventType:
    OPEN = 0
    CREATE = 1
    DELETE = 2
    ENCRYPT = 3
    READ = 4
    WRITE = 5
    SCAN = 6
    RENAME = 7
    NET_SOCKET = 8
    NET_CONNECT = 9

# see <bpf.h>
EVENT_TYPES = EventType.NET_CONNECT + 1

EVENT_TYPE_NAMES = [
    "Open",
    "Crea",
    "Del",
    "Enc",
    "Read",
    "Writ",
    "Scan",
    "Ren",
    "Sock",
    "Conn",
]

THRESHOLD_LETTERS = [
    "O",
    "C",
    "D",
    "E",
    "R",
    "W",
    "S",
    "N",
    "K",
    "T",
]

THRESHOLD_HEADERS = [
    "OPEN",
    "CREATE",
    "DELETE",
    "ENCRYPT",
    "READ",
    "WRITE",
    "SCAN",
    "RENAME",
    "NET_SOCKET",
    "NET_CONNECT",
]

class Config(ctypes.Structure):
    _pack_ = 1  # Pack struct to avoid padding issues
    _fields_ = [
        ('thresholds', ctypes.c_uint16 * EVENT_TYPES),  # 20 bytes
        ('reset_period_ns', ctypes.c_uint64),  # time_t is u64, not u32!
        ('min_severity', ctypes.c_uint8),  # 1 byte
    ]

def update_config(b: BPF):
    # 10 billion nanoseconds = 10 seconds
    thresholds = ctypes.c_uint16 * EVENT_TYPES
    b['config'][ctypes.c_int(0)] = Config(
        thresholds(
            40,   # open 
            20,    # create 
            5,    # delete 
            20,    # encrypt 
            40,  # read 
            20,  # write 
            40,  # scan (getdents64) 
            10,    # rename 
            50,    # net socket 
            50,     # net connect 
        ),
        5_000_000_000,
        0  # min_severity: 0=all, 1=threshold crossed, 2=pattern matched only
    )

# see <bpf.h>
class Pattern(ctypes.Structure):
    _fields_ = [
        ('bitmap', ctypes.c_uint32),
        ('bitmask', ctypes.c_uint32),
    ]

def encode_pattern(sequence):
    bitmap = 0
    bitmask = 0
    for event in sequence:
        bitmap = (bitmap << BITS_PER_EVENT) | event
        bitmask = (bitmask << BITS_PER_EVENT) | EVENT_MASK
    return Pattern(bitmap, bitmask)

def update_patterns(b: BPF):
    pattern_sequences = [ # To add more patterns here, you need to add more events to the EventType enum, and add more patterns to the update_patterns function.
        
        [EventType.ENCRYPT, EventType.OPEN, EventType.NET_SOCKET, EventType.NET_CONNECT],

        [ EventType.READ, EventType.WRITE, EventType.WRITE, EventType.RENAME],
        
        [EventType.ENCRYPT, EventType.ENCRYPT, EventType.DELETE],      

        [EventType.OPEN, EventType.READ, EventType.WRITE, EventType.OPEN, EventType.READ, EventType.WRITE],

        [EventType.READ, EventType.READ, EventType.WRITE, EventType.RENAME],

        [EventType.CREATE, EventType.CREATE, EventType.WRITE, EventType.ENCRYPT],

        [EventType.WRITE, EventType.WRITE, EventType.WRITE, EventType.RENAME],

        [EventType.OPEN, EventType.SCAN, EventType.SCAN, EventType.CREATE],
    ]
    values = [encode_pattern(seq) for seq in pattern_sequences]
    patterns = b['patterns']
    for k,v in enumerate(values):
        patterns[ctypes.c_int(k)] = v

# see <bpf.h>
class ThresholdPattern(ctypes.Structure):
    _fields_ = [
        ('bitmap', ctypes.c_uint16),
        ('bitmask', ctypes.c_uint16),
    ]

def encode_threshold_pattern(sequence):
    """
    Encode threshold pattern from event type sequence.
    Example: [EventType.OPEN, EventType.READ, EventType.WRITE, EventType.RENAME]
    -> bitmap = 0x00B1 (bits 0,4,5,7 set)
    -> bitmask = 0x00B1 (exact match)
    """
    bitmap = 0
    bitmask = 0
    for event_type in sequence:
        bitmap |= (1 << event_type)
        bitmask |= (1 << event_type)
    return ThresholdPattern(bitmap, bitmask)

def update_threshold_patterns(b: BPF):
    """
    Update threshold patterns in BPF map.
    Patterns are combinations of event types that when crossed together indicate ransomware.
    """
    threshold_pattern_sequences = [
        # To add more threshold patterns here, you need to add more events to the EventType enum, and add more threshold patterns to the update_threshold_patterns function.
        [EventType.OPEN, EventType.READ, EventType.WRITE, EventType.RENAME],
        [EventType.OPEN, EventType.CREATE, EventType.DELETE, EventType.ENCRYPT],
    ]
    
    values = [encode_threshold_pattern(seq) for seq in threshold_pattern_sequences]
    threshold_patterns = b['threshold_patterns']
    for k, v in enumerate(values):
        threshold_patterns[ctypes.c_int(k)] = v

# see <bpf.h>
class Flags(ctypes.Structure):
    _fields_ = [
        ('severity', ctypes.c_uint8),
        ('pattern_id', ctypes.c_uint8),
        ('threshold_pattern_id', ctypes.c_uint8),
        ('thresholds_crossed', ctypes.c_uint16),
    ]

# see <bpf.h> and <linux/sched.h>
FILENAME_SIZE = 64
TASK_COMM_LEN = 16
class Event(ctypes.Structure):
    _fields_ = [
        ('ts', ctypes.c_uint64),
        ('pid', ctypes.c_uint32),
        ('type', ctypes.c_uint),
        ('flags', Flags),
        ('event_bitmap', ctypes.c_uint32),  # Bitmap of last 8 events
        ('filename', ctypes.c_char * FILENAME_SIZE),
        ('comm', ctypes.c_char * TASK_COMM_LEN),
    ]

def decode_type(t: ctypes.c_uint) -> str:
    try:
        return EVENT_TYPE_NAMES[t]
    except IndexError:
        return f"T{t}"

def decode_severity(s: ctypes.c_uint8) -> str:
    name = {0: "OK", 1: "MIN", 2: "MAJ"}
    return name[s]

def decode_pattern(p: ctypes.c_uint8) -> str:
    return "P%d" % p if p > 0 else "-"

def decode_threshold_pattern(p: ctypes.c_uint8) -> str:
    return "V%d" % p if p > 0 else "-"

def decode_thresholds(t: ctypes.c_uint16) -> str:
    output = []
    for idx, letter in enumerate(THRESHOLD_LETTERS):
        output.append(letter if t & (1 << idx) else "-")
    return "".join(output)

def unpack_thresholds(t: ctypes.c_uint16):
    output = []
    for k in range(EVENT_TYPES):
        if t & (1 << k):
            output.append(1)
        else:
            output.append(0)
    return output

def decode_bitmap(bitmap: ctypes.c_uint32) -> str:
    """Decode bitmap to show last 8 events as string (e.g., 'O-C-E-D')"""
    if bitmap == 0xFFFFFFFF:  # Empty bitmap
        return "-"
    
    events = []
    for i in range(BITMAP_EVENTS):
        event_type = (bitmap >> (i * BITS_PER_EVENT)) & EVENT_MASK
        if event_type == 0xF:  # Empty slot
            break
        try:
            events.append(EVENT_TYPE_NAMES[event_type])
        except IndexError:
            events.append(f"T{event_type}")
    
    if not events:
        return "-"
    
    # Return as comma-separated string (e.g., "O,C,E,D")
    return ",".join(events)

# find library pathname
def find_lib(lib: str) -> str:
    # Common library search paths
    search_paths = [
        '/usr/lib/',
        '/usr/lib/x86_64-linux-gnu/',
        '/usr/lib64/',
        '/lib/',
        '/lib/x86_64-linux-gnu/',
        '/lib64/',
        '/opt/',
        '/usr/local/lib/',
    ]
    
    for path in search_paths:
        if not os.path.exists(path):
            continue
        for root, _, files in os.walk(path):
            if lib in files:
                return os.path.join(root, lib)
    
    # Also try direct paths (for common locations)
    direct_paths = [
        f'/usr/lib/x86_64-linux-gnu/{lib}',
        f'/usr/lib/{lib}',
        f'/lib/x86_64-linux-gnu/{lib}',
        f'/lib/{lib}',
    ]
    for path in direct_paths:
        if os.path.exists(path):
            return path
    
    return None

def save_data(event: Event, writer_obj):
    # write data to csv
    try:
        filename_str = event.filename.decode('utf-8', errors='replace') if event.filename else ''
        writer_obj.writerow([event.ts,
                             event.pid, 
                             event.type, 
                             event.flags.severity, 
                             event.flags.pattern_id, 
                             *unpack_thresholds(event.flags.thresholds_crossed), # transforms to multiple args/columns
                             filename_str])
        # Flush immediately to ensure data is written
        if hasattr(writer_obj, 'flush'):
            writer_obj.flush()
    except Exception as e:
        # Don't crash on CSV write errors, just print warning
        print(f"Warning: Failed to write CSV data: {e}", file=sys.stderr)

# Global variable to store min_severity from config
min_severity = 2

# Track killed PIDs to avoid killing multiple times
killed_pids = set()

# Global variable to check if terminal supports colors (check once)
_terminal_supports_color = None

def kill_all_processes_by_comm(comm_name):
    """
    Kill ALL processes with the same comm name (for multi-process ransomware).
    Important: Multi-threaded ransomware often has many processes with the same comm name.
    
    Use /proc to find processes with exact comm name (avoid pgrep -f to avoid false positive).
    """
    global killed_pids
    killed_count = 0
    my_pid = os.getpid()  # Avoid killing the main detector
    
    try:
        # Find all processes in /proc
        pids = []
        for proc_entry in os.listdir('/proc'):
            if not proc_entry.isdigit():
                continue
            
            target_pid = int(proc_entry)
            
            # Skip main detector and processes that have been killed
            if target_pid == my_pid or target_pid in killed_pids:
                continue
            
            # Read comm name from /proc/PID/comm
            try:
                comm_path = f'/proc/{target_pid}/comm'
                if os.path.exists(comm_path):
                    with open(comm_path, 'r') as f:
                        proc_comm = f.read().strip()
                        # Match exact comm name (no partial match)
                        if proc_comm == comm_name:
                            pids.append(target_pid)
            except (IOError, OSError, ValueError):
                # Process has died or does not have read permission (ignore)
                continue
        
        # Kill all processes immediately (ignore errors)
        for target_pid in pids:
            try:
                os.kill(target_pid, signal.SIGKILL)
                killed_pids.add(target_pid)
                killed_count += 1
                print(f"[KILL] Killed PID {target_pid} (comm={comm_name})", file=sys.stderr)
            except (ProcessLookupError, PermissionError):
                pass    
            except Exception:
                pass
        
        if killed_count > 0:    # Print message if any processes were killed
            print(f"[KILL] Killed {killed_count} processes with comm '{comm_name}'", file=sys.stderr)
    except Exception as e:
        print(f"[KILL] Error finding processes by comm '{comm_name}': {e}", file=sys.stderr)

def kill_process_group(pgid):
    """
    Kill all process group by killpg() method.
    Important for multi-threaded ransomware.
    """
    try:
        # Kill all process group (all processes in group)
        os.killpg(pgid, signal.SIGKILL)
        print(f"[KILL] Killed process group {pgid} (killpg)", file=sys.stderr)
        return True
    except ProcessLookupError:
        # Process group does not exist
        return False
    except PermissionError:
        print(f"[KILL] Permission denied for process group {pgid}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"[KILL] Error killing process group {pgid}: {e}", file=sys.stderr)
        return False

def kill_process_tree(pid, comm_name=None):
    """
    Kill process tree FAST - optimize for multi-process/multi-threaded ransomware.
    
    Strategy (Optimize for multi-threaded ransomware):
    1. Kill PID immediately by SIGKILL
    2. Kill process group (PGID) - kill all threads/processes in group
    3. Kill all processes with the same comm name (important for multi-process ransomware)
    4. Kill all children processes
    """
    global killed_pids
    
    # Avoid killing the same process tree multiple times
    if pid in killed_pids:
        return
    
    killed_pids.add(pid)
    
    # STEP 1: Kill PID immediately
    try:
        os.kill(pid, signal.SIGKILL)
        print(f"[KILL] KILLED PID {pid} IMMEDIATELY (SIGKILL)", file=sys.stderr)
    except ProcessLookupError:
        pass
    except PermissionError:
        print(f"[KILL] Permission denied for PID {pid} (need root)", file=sys.stderr)
        return
    except Exception as e:
        print(f"[KILL] Error killing PID {pid}: {e}", file=sys.stderr)
    
    # STEP 2: Kill process group (PGID) - Important for multi-threaded ransomware
    try:
        pgid = os.getpgid(pid)
        if pgid and pgid not in killed_pids:
            killed_pids.add(pgid)
            if kill_process_group(pgid):
                print(f"[KILL] Killed process group {pgid} (all threads/processes in group)", file=sys.stderr)
    except (ProcessLookupError, OSError):
        pass
    except Exception as e:
        print(f"[KILL] Warning: Could not get/kill process group: {e}", file=sys.stderr)
    
    # STEP 3: Kill all processes with the same comm name - Important for multi-process ransomware
    if comm_name:
        kill_all_processes_by_comm(comm_name)
    
    # STEP 4: Find and kill children processes
    def find_children_fast(parent_pid):
        """Find children quickly - only use /proc"""
        children = []
        try:
            proc_path = f"/proc/{parent_pid}/task/{parent_pid}/children"
            if os.path.exists(proc_path):
                with open(proc_path, 'r') as f:
                    child_pids = f.read().strip().split()
                    for child_pid_str in child_pids:
                        if child_pid_str.isdigit():
                            child_pid = int(child_pid_str)
                            if child_pid not in killed_pids:
                                children.append(child_pid)
                                killed_pids.add(child_pid)
                                children.extend(find_children_fast(child_pid))
        except:
            pass
        return children
    
    # Find and kill children
    try:
        children = find_children_fast(pid)
        if children:
            print(f"[KILL] Found {len(children)} child processes, killing...", file=sys.stderr)
            for child_pid in children:
                try:
                    os.kill(child_pid, signal.SIGKILL)
                    print(f"[KILL] Killed child PID {child_pid}", file=sys.stderr)
                except (ProcessLookupError, PermissionError):
                    pass
                except Exception:
                    pass
    except Exception as e:
        print(f"[KILL] Warning: Could not find all children: {e}", file=sys.stderr)

def terminal_supports_color():
    """Check if terminal supports ANSI color codes"""
    global _terminal_supports_color
    if _terminal_supports_color is None:
        # Force color if FORCE_COLOR environment variable is set
        if os.getenv('FORCE_COLOR') is not None:
            _terminal_supports_color = True
            return _terminal_supports_color
        
        # Check if stdout is a TTY and TERM is not 'dumb'
        _terminal_supports_color = (
            sys.stdout.isatty() and 
            os.getenv('TERM') != 'dumb' and
            os.getenv('NO_COLOR') is None  # Respect NO_COLOR environment variable
        )
    return _terminal_supports_color

def print_event(_ctx, data, _size):
    event = ctypes.cast(data, ctypes.POINTER(Event)).contents
    
    
    # Check if should be in log.csv (original logic):
    # - emit_always events (OPEN, CREATE, DELETE, ENCRYPT, RENAME, NET_SOCKET, NET_CONNECT): if severity >= min_severity
    # - analytics events (READ, WRITE, SCAN): only if pattern matched (severity >= S_MAJOR = 2)
    emit_always_types = [EventType.SCAN, EventType.OPEN, EventType.CREATE, EventType.DELETE, EventType.ENCRYPT, EventType.RENAME, EventType.NET_SOCKET, EventType.NET_CONNECT]
    is_emit_always = event.type in emit_always_types
    
    should_log = False
    should_print = False
    
    if is_emit_always:
        # emit_always events: log and print if severity >= min_severity
        should_log = (event.flags.severity >= min_severity)
        should_print = should_log
    else:
        # analytics events: only log and print if pattern matched (severity >= S_MAJOR = 2)
        should_log = (event.flags.severity >= 2)
        #should_print = should_log
    
    # Save to log.csv only if should_log (original logic)
    if should_log:
        save_data(event, writer)
    
    # Print to terminal only if should_print
    if should_print:
        # ANSI color codes (try both \033 and \x1b)
        RED = '\x1b[91m'      # Red (bright red) - use \x1b instead of \033
        YELLOW = '\x1b[93m'  # Yellow (bright yellow)
        RESET = '\x1b[0m'     # Reset to default color
        
        # Format output string
        pattern_str = decode_pattern(event.flags.pattern_id)
        threshold_pattern_str = decode_threshold_pattern(event.flags.threshold_pattern_id)
        pattern_display = pattern_str if pattern_str != "-" else threshold_pattern_str
        
        output = "%-6d %-6d %-16s %-4s %-4s %-20s %-5s %-10s %-64s" % (
            int(event.ts / 1e6),
            event.pid,
            event.comm.decode('utf-8'),
            decode_type(event.type), 
            decode_severity(event.flags.severity),
            decode_bitmap(event.event_bitmap),  # Bitmap of last 8 events
            pattern_display, 
            decode_thresholds(event.flags.thresholds_crossed), 
            event.filename.decode('utf-8'))
        
        # In color based on severity if terminal supports colors
        if terminal_supports_color():
            if event.flags.severity == 2:  # S_MAJOR = 2
                sys.stdout.write(f"{RED}{output}{RESET}\n")
            elif event.flags.severity == 1:  # S_MINOR = 1
                sys.stdout.write(f"{YELLOW}{output}{RESET}\n")
            else:
                sys.stdout.write(f"{output}\n")
            sys.stdout.flush()
        else:
            # No color support, in normal text (print without color)
            print(output, flush=True)
    
    # LARM-like mechanism: Kill process tree when MAJOR severity detected (alert message)
    # Kill all "process tree" of ransomware to save data
    if event.flags.severity == 2:  # S_MAJOR = 2
        comm_name = event.comm.decode('utf-8')
        pattern_id = decode_pattern(event.flags.pattern_id)
        
        # Kill IMMEDIATELY - no wait, no print message before
        # Goal: Save data by killing as quickly as possible
        # IMPORTANT: Pass comm_name to kill ALL processes with the same name (multi-process ransomware)
        kill_process_tree(event.pid, comm_name=comm_name)
        
        # In alert message AFTER killing (to avoid slowing down)
        if terminal_supports_color():
            RED = '\x1b[91m'
            BOLD = '\x1b[1m'
            GREEN = '\x1b[92m'
            RESET = '\x1b[0m'
            alert_msg = f"\n{RED}{BOLD}------------------------[ALERT]  RANSOMWARE DETECTED & KILLED!{RESET}"
            print(alert_msg, file=sys.stderr)
            print(f"{GREEN}  ------------------------PID={event.pid}, Pattern={pattern_id}, Comm={comm_name}{RESET}", file=sys.stderr)
    
        else:
            print(f"\n------------------------[ALERT]  RANSOMWARE DETECTED & KILLED!", file=sys.stderr)
            print(f"  ------------------------PID={event.pid}, Pattern={pattern_id}, Comm={comm_name}", file=sys.stderr)
            

def runas_root() -> bool:
    return os.getuid() == 0

def main():
    global min_severity
    b = BPF(src_file="bpf.c", cflags=["-Wno-macro-redefined"], debug=0)

    # send config + patterns to ebpf programs
    update_config(b)
    update_patterns(b)
    update_threshold_patterns(b)
    
    # Read min_severity from config for use in filtering
    try:
        config_map = b['config']
        config_data = config_map[ctypes.c_int(0)]
        min_severity = config_data.min_severity
    except:
        min_severity = 0  # default value

    # the path to libcrypto may differ from OS to OS
    # check symbol address with nm -gD /path/to/lib.so or readelf -Ws --dyn-syms /path/to/lib.so
    for lib in ['libcrypto.so.1.1', 'libcrypto.so.3']:
        pathname = find_lib(lib)
        if pathname:
            # High-level OpenSSL encryption functions
            b.attach_uprobe(name=pathname, sym="EVP_EncryptInit_ex", fn_name="trace_encrypt1")
            b.attach_uprobe(name=pathname, sym="EVP_CipherInit_ex", fn_name="trace_encrypt1")
            b.attach_uprobe(name=pathname, sym="EVP_SealInit", fn_name="trace_encrypt2")
            # Additional OpenSSL encryption functions
            try:
                b.attach_uprobe(name=pathname, sym="EVP_EncryptUpdate", fn_name="trace_encrypt_update")
            except:
                pass  # Function may not exist in older OpenSSL versions
            try:
                b.attach_uprobe(name=pathname, sym="EVP_EncryptFinal_ex", fn_name="trace_encrypt_final")
            except:
                pass
            try:
                b.attach_uprobe(name=pathname, sym="EVP_DigestInit_ex", fn_name="trace_digest_init")
            except:
                pass
            # Low-level AES functions
            try:
                b.attach_uprobe(name=pathname, sym="AES_encrypt", fn_name="trace_aes_encrypt")
            except:
                pass
            try:
                b.attach_uprobe(name=pathname, sym="AES_cbc_encrypt", fn_name="trace_aes_cbc_encrypt")
            except:
                pass
            try:
                b.attach_uprobe(name=pathname, sym="AES_ctr128_encrypt", fn_name="trace_aes_ctr_encrypt")
            except:
                pass
    
    # libgcrypt (GNU Crypto Library) - alternative to OpenSSL
    for lib in ['libgcrypt.so.20', 'libgcrypt.so.11', 'libgcrypt.so']:
        pathname = find_lib(lib)
        if pathname:
            try:
                b.attach_uprobe(name=pathname, sym="gcry_cipher_encrypt", fn_name="trace_gcry_cipher_encrypt")
            except:
                pass
            try:
                b.attach_uprobe(name=pathname, sym="gcry_cipher_setkey", fn_name="trace_gcry_cipher_setkey")
            except:
                pass
 
    events_map = b['events']
    events_map.open_ring_buffer(print_event)

    # Test color support and display information
    if terminal_supports_color():
        print("Printing file & crypto events, ctrl-c to exit. (Color enabled)")
    else:
        print("Printing file & crypto events, ctrl-c to exit. (Color disabled - not a TTY or TERM=dumb)")
        print("  Tip: Run in a terminal (not redirected) to see colors")
    
    print("%-6s %-6s %-16s %-4s %-4s %-20s %-5s %-10s %-64s" % 
          ("TS", "PID", "COMM", "TYPE", "FLAG", "BITMAP", "PATT", "THRESH", "FILENAME"))
    # headers for both CSV files
    writer.writerow(
        ["TS", "PID", "TYPE", "FLAG", "PATTERN", *THRESHOLD_HEADERS, "FILENAME"]
    )
    # loop with callback to print events
    try:
        while 1:
            b.ring_buffer_consume()
            time.sleep(0.5)
    except KeyboardInterrupt:
        f.close()
        sys.exit()
        


if __name__ == '__main__':
    if not runas_root():
        print("You must run this program as root or with sudo.")
        sys.exit()
    
    # log.csv: only events that would be emitted (original logic)
    f = open('log.csv', 'w', encoding='UTF8', newline='')
    writer = csv.writer(f)
    
    
    try:
        main()
    except Exception as e:
        print(f"Error in detector: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        f.close()
        sys.exit(1)
