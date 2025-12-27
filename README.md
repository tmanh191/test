# eBPF Ransomware Detector (Enhanced)

An enhanced eBPF-based ransomware detection system with automatic process termination capabilities.

## Overview

This project is an improved version of [ebpfangel](https://github.com/TomasPhilippart/ebpfangel) with additional features for detecting and automatically killing ransomware processes.

## Features

- **Real-time ransomware detection** using eBPF (Extended Berkeley Packet Filter)
- **Pattern-based detection** for suspicious file operations
- **Threshold-based detection** for event count monitoring
- **Automatic process termination** when ransomware is detected
- **Multi-process ransomware handling** - kills entire process trees and processes with same comm name
- **Comprehensive event logging** to CSV files
- **Color-coded terminal output** for severity levels

## Key Improvements Over Original ebpfangel

- Enhanced process killing mechanism (process tree, process group, and comm-based killing)
- Improved pattern matching logic for better detection accuracy
- Threshold pattern matching for combination-based detection
- Better handling of multi-threaded and multi-process ransomware
- Optimized bitmap-based event tracking
- Enhanced logging and reporting capabilities

## Requirements

- Linux kernel with eBPF support (4.18+)
- Python 3.6+
- BCC (BPF Compiler Collection)
- Root/sudo privileges

## Installation

1. Install BCC on your system:
   ```bash
   # Ubuntu/Debian
   sudo apt-get install bpfcc-tools python3-bpfcc
   
   # Or follow BCC installation guide: https://github.com/iovisor/bcc
   ```

2. Clone this repository:
   ```bash
   git clone https://github.com/tmanh191/eBPF-ransomware-reactive-detector.git
   cd eBPF-ransomware-reactive-detector
   ```


## Usage

### Quick Start

Run the detector with root privileges:

```bash
sudo python3 detector.py
```

```bash
python3 validate.py
```

This checks:
- Python version
- Required files
- BCC availability
- BPF program compilation

The detector will:
- Monitor file operations (open, create, delete, read, write, rename)
- Monitor encryption operations (OpenSSL, libgcrypt)
- Monitor network operations (socket, connect)
- Detect suspicious patterns and threshold violations
- Automatically kill detected ransomware processes
- Log events to `log.csv`

Press `Ctrl+C` to stop the detector.

## Configuration

Edit the `update_config()` function in `detector.py` to adjust:
- Event thresholds
- Reset period
- Minimum severity for reporting

Edit `update_patterns()` and `update_threshold_patterns()` to customize detection patterns.

## Output

- **Terminal**: Real-time color-coded event display
- **log.csv**: Detailed event log with timestamps, PIDs, patterns, and thresholds

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Attribution

This project is based on [ebpfangel](https://github.com/TomasPhilippart/ebpfangel) by TomasPhilippart.

Original ebpfangel is also licensed under the MIT License.

## Disclaimer

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.



## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

**Note:** This is an enhanced fork of [ebpfangel](https://github.com/TomasPhilippart/ebpfangel). If you're interested in contributing features back to the original project, please coordinate with the original author.

## Acknowledgments

- Original ebpfangel project by TomasPhilippart
- BCC project for eBPF tooling
- Linux kernel eBPF subsystem

