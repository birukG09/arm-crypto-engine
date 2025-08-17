# ArmAsm-CryptoEngine Makefile
# Top-level build orchestration

.PHONY: all clean test bench examples stm32f4 rpi host help

# Default target
all: stm32f4

# Help target
help:
	@echo "ArmAsm-CryptoEngine Build System"
	@echo "Available targets:"
	@echo "  all        - Build default target (STM32F4)"
	@echo "  stm32f4    - Build for STM32F4 (Cortex-M4)"
	@echo "  rpi        - Build for Raspberry Pi (Cortex-A53)"
	@echo "  host       - Build host version for testing"
	@echo "  test       - Run test suite"
	@echo "  bench      - Run benchmarks"
	@echo "  examples   - Build example applications"
	@echo "  clean      - Clean all build artifacts"
	@echo "  help       - Show this help message"

# STM32F4 target
stm32f4:
	mkdir -p build/stm32f4
	cd build/stm32f4 && cmake -DCMAKE_BUILD_TYPE=Release -DSTM32F4_TARGET=ON ../..
	cmake --build build/stm32f4 -j$(shell nproc)

# Raspberry Pi target
rpi:
	mkdir -p build/rpi
	cd build/rpi && cmake -DCMAKE_BUILD_TYPE=Release -DRPI_TARGET=ON ../..
	cmake --build build/rpi -j$(shell nproc)

# Host build for testing
host:
	mkdir -p build/host
	cd build/host && cmake -DCMAKE_BUILD_TYPE=Debug -DHOST_TESTS=ON ../..
	cmake --build build/host -j$(shell nproc)

# Run tests
test: host
	cd build/host && ctest --output-on-failure

# Build examples
examples: stm32f4
	@echo "Examples built as part of main target"

# Run benchmarks
bench: stm32f4
	@echo "Benchmark binary: build/stm32f4/bench/bench_crypto"

# Clean build artifacts
clean:
	rm -rf build/

# Development helpers
format:
	find include src tests examples -name "*.c" -o -name "*.h" | xargs clang-format -i

lint:
	python3 scripts/asm_style.py src/asm/

# Generate test vectors
vectors:
	python3 scripts/test_vectors.py > tests/vectors/generated_vectors.h
