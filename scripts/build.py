#!/usr/bin/env python3
"""
Build script for ArmAsm-CryptoEngine
Provides high-level build orchestration and validation
"""

import os
import sys
import subprocess
import argparse
import shutil
from pathlib import Path

def run_command(cmd, cwd=None, check=True):
    """Run a command and return the result"""
    print(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    
    if check and result.returncode != 0:
        print(f"Command failed with return code {result.returncode}")
        print(f"stdout: {result.stdout}")
        print(f"stderr: {result.stderr}")
        sys.exit(1)
    
    return result

def check_toolchain(target):
    """Check if required toolchain is available"""
    if target == "stm32f4":
        try:
            run_command(["arm-none-eabi-gcc", "--version"])
            print("✓ ARM GCC toolchain found")
        except FileNotFoundError:
            print("✗ arm-none-eabi-gcc not found. Install with:")
            print("  sudo apt-get install gcc-arm-none-eabi")
            return False
    elif target == "rpi":
        try:
            run_command(["aarch64-linux-gnu-gcc", "--version"])
            print("✓ AArch64 GCC toolchain found")
        except FileNotFoundError:
            print("✗ aarch64-linux-gnu-gcc not found. Install with:")
            print("  sudo apt-get install gcc-aarch64-linux-gnu")
            return False
    
    return True

def build_target(target, build_type="Release", clean=False):
    """Build a specific target"""
    build_dir = Path("build") / target
    
    if clean and build_dir.exists():
        print(f"Cleaning {build_dir}")
        shutil.rmtree(build_dir)
    
    build_dir.mkdir(parents=True, exist_ok=True)
    
    # CMake configuration
    cmake_args = [
        "cmake",
        "-DCMAKE_BUILD_TYPE=" + build_type,
        "../.."
    ]
    
    if target == "stm32f4":
        cmake_args.append("-DSTM32F4_TARGET=ON")
    elif target == "rpi":
        cmake_args.append("-DRPI_TARGET=ON")
    elif target == "host":
        cmake_args.append("-DHOST_TESTS=ON")
    
    run_command(cmake_args, cwd=build_dir)
    
    # Build
    run_command(["cmake", "--build", ".", "-j", str(os.cpu_count())], cwd=build_dir)
    
    print(f"✓ {target} build completed successfully")

def run_tests():
    """Run the test suite"""
    build_dir = Path("build") / "host"
    
    if not build_dir.exists():
        print("Host build not found, building...")
        build_target("host", "Debug")
    
    print("Running test suite...")
    run_command(["ctest", "--output-on-failure"], cwd=build_dir)
    print("✓ All tests passed")

def analyze_binary(target):
    """Analyze the built binary for size and security"""
    build_dir = Path("build") / target
    lib_path = build_dir / "libarmcrypto.a"
    
    if not lib_path.exists():
        print(f"Library not found: {lib_path}")
        return
    
    # Size analysis
    if target == "stm32f4":
        size_cmd = ["arm-none-eabi-size", str(lib_path)]
    else:
        size_cmd = ["size", str(lib_path)]
    
    print("\nBinary size analysis:")
    run_command(size_cmd)
    
    # Symbol analysis
    if target == "stm32f4":
        nm_cmd = ["arm-none-eabi-nm", "--size-sort", str(lib_path)]
    else:
        nm_cmd = ["nm", "--size-sort", str(lib_path)]
    
    print("\nLargest symbols:")
    result = run_command(nm_cmd, check=False)
    if result.returncode == 0:
        lines = result.stdout.strip().split('\n')
        for line in lines[-10:]:  # Show top 10 largest
            print(line)

def main():
    parser = argparse.ArgumentParser(description="Build ArmAsm-CryptoEngine")
    parser.add_argument("target", choices=["stm32f4", "rpi", "host", "all"],
                       help="Build target")
    parser.add_argument("--clean", action="store_true",
                       help="Clean before building")
    parser.add_argument("--debug", action="store_true",
                       help="Build in debug mode")
    parser.add_argument("--test", action="store_true",
                       help="Run tests after building")
    parser.add_argument("--analyze", action="store_true",
                       help="Analyze binary after building")
    
    args = parser.parse_args()
    
    build_type = "Debug" if args.debug else "Release"
    
    if args.target == "all":
        targets = ["host", "stm32f4", "rpi"]
    else:
        targets = [args.target]
    
    for target in targets:
        if not check_toolchain(target):
            continue
        
        print(f"\n=== Building {target} ===")
        build_target(target, build_type, args.clean)
        
        if args.analyze:
            analyze_binary(target)
    
    if args.test:
        print(f"\n=== Running Tests ===")
        run_tests()

if __name__ == "__main__":
    main()
