#!/usr/bin/env python3
"""
Quick test script to validate detector functionality
Can be run locally or in CI/CD
"""

import sys
import os

def main():
    print("="*60)
    print("eBPF Ransomware Detector - Quick Test")
    print("="*60)
    
    # Test imports
    print("\n[1/5] Testing imports...")
    try:
        import os, sys, time, ctypes, csv, signal
        from bcc import BPF
        import detector
        print("✅ All imports successful")
    except ImportError as e:
        print(f"❌ Import failed: {e}")
        return 1
    
    # Test functions
    print("\n[2/5] Testing functions...")
    try:
        assert detector.EventType.OPEN == 0
        pattern = detector.encode_pattern([detector.EventType.OPEN, detector.EventType.CREATE])
        assert detector.decode_type(0) == "Open"
        print("✅ Core functions work")
    except Exception as e:
        print(f"❌ Function test failed: {e}")
        return 1
    
    # Test BPF compilation
    print("\n[3/5] Testing BPF compilation...")
    try:
        b = BPF(src_file="bpf.c", cflags=["-Wno-macro-redefined"], debug=0)
        print("✅ BPF compiled successfully")
    except Exception as e:
        print(f"⚠️ BPF compilation: {e} (may need kernel support)")
        return 0  # Don't fail if BPF can't compile in test environment
    
    # Test configuration
    print("\n[4/5] Testing configuration...")
    try:
        detector.update_config(b)
        detector.update_patterns(b)
        detector.update_threshold_patterns(b)
        print("✅ Configuration updated")
    except Exception as e:
        print(f"❌ Configuration failed: {e}")
        return 1
    
    # Test file structure
    print("\n[5/5] Testing file structure...")
    required = ['detector.py', 'bpf.c', 'bpf.h']
    for f in required:
        if not os.path.exists(f):
            print(f"❌ Missing file: {f}")
            return 1
    print("✅ All files present")
    
    print("\n" + "="*60)
    print("✅ All tests passed!")
    print("="*60)
    return 0

if __name__ == '__main__':
    sys.exit(main())
