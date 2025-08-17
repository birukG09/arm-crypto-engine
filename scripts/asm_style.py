#!/usr/bin/env python3
"""
Assembly style checker for ArmAsm-CryptoEngine
Enforces coding standards for ARM assembly files
"""

import re
import sys
import argparse
from pathlib import Path

class AsmStyleChecker:
    def __init__(self):
        self.errors = []
        self.warnings = []
    
    def check_file(self, filepath):
        """Check a single assembly file"""
        print(f"Checking {filepath}")
        
        with open(filepath, 'r') as f:
            lines = f.readlines()
        
        self.check_syntax_directive(lines, filepath)
        self.check_function_format(lines, filepath)
        self.check_register_usage(lines, filepath)
        self.check_constant_time(lines, filepath)
        self.check_comments(lines, filepath)
    
    def check_syntax_directive(self, lines, filepath):
        """Check for .syntax unified directive"""
        has_syntax = any('.syntax unified' in line for line in lines[:10])
        if not has_syntax:
            self.errors.append(f"{filepath}: Missing '.syntax unified' directive")
    
    def check_function_format(self, lines, filepath):
        """Check function prologue/epilogue format"""
        for i, line in enumerate(lines, 1):
            # Check for function labels
            if re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*:$', line.strip()):
                func_name = line.strip()[:-1]
                
                # Look for .type directive
                type_found = False
                for j in range(max(0, i-3), min(len(lines), i+3)):
                    if f'.type {func_name}, %function' in lines[j]:
                        type_found = True
                        break
                
                if not type_found:
                    self.errors.append(f"{filepath}:{i}: Missing .type directive for function {func_name}")
    
    def check_register_usage(self, lines, filepath):
        """Check register usage patterns"""
        for i, line in enumerate(lines, 1):
            # Check for proper register preservation
            if 'push' in line.lower():
                # Should preserve callee-saved registers
                if not re.search(r'\{.*r[4-8].*\}', line):
                    if re.search(r'\{.*r[0-3].*\}', line):
                        self.warnings.append(f"{filepath}:{i}: Consider preserving callee-saved registers")
            
            # Check for data-dependent branches (potential timing leaks)
            if re.search(r'\b(beq|bne|blt|bgt|ble|bge)\b', line.lower()):
                self.warnings.append(f"{filepath}:{i}: Conditional branch - verify constant-time behavior")
    
    def check_constant_time(self, lines, filepath):
        """Check for potential constant-time violations"""
        for i, line in enumerate(lines, 1):
            # Look for table lookups that might not be constant-time
            if re.search(r'ldr.*\[.*r\d+.*\]', line.lower()):
                if 'sbox' in line.lower() or 'table' in line.lower():
                    self.warnings.append(f"{filepath}:{i}: Table lookup - verify constant-time implementation")
            
            # Check for multiplication patterns that might vary in time
            if re.search(r'\b(mul|mla|mls)\b', line.lower()):
                self.warnings.append(f"{filepath}:{i}: Multiplication - verify constant-time on target CPU")
    
    def check_comments(self, lines, filepath):
        """Check comment quality and documentation"""
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            
            # Functions should have documentation
            if re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*:$', stripped):
                # Look for comment block above function
                has_doc = False
                for j in range(max(0, i-10), i):
                    if lines[j].strip().startswith('@') or lines[j].strip().startswith('//'):
                        has_doc = True
                        break
                
                if not has_doc:
                    self.warnings.append(f"{filepath}:{i}: Function lacks documentation comment")
    
    def report(self):
        """Report all errors and warnings"""
        if self.errors:
            print("\nERRORS:")
            for error in self.errors:
                print(f"  {error}")
        
        if self.warnings:
            print("\nWARNINGS:")
            for warning in self.warnings:
                print(f"  {warning}")
        
        print(f"\nSummary: {len(self.errors)} errors, {len(self.warnings)} warnings")
        return len(self.errors) == 0

def main():
    parser = argparse.ArgumentParser(description="Check ARM assembly style")
    parser.add_argument("paths", nargs="+", help="Paths to check")
    parser.add_argument("--fix", action="store_true", help="Auto-fix issues where possible")
    
    args = parser.parse_args()
    
    checker = AsmStyleChecker()
    
    for path_str in args.paths:
        path = Path(path_str)
        
        if path.is_file() and path.suffix in ['.s', '.S']:
            checker.check_file(path)
        elif path.is_dir():
            for asm_file in path.rglob("*.s"):
                checker.check_file(asm_file)
            for asm_file in path.rglob("*.S"):
                checker.check_file(asm_file)
    
    success = checker.report()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
