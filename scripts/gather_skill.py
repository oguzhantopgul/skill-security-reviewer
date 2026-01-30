#!/usr/bin/env python3
"""
Skill Content Gatherer for Security Review

Recursively collects all files in a skill directory and outputs them
in a format suitable for security analysis.

Usage:
    python gather_skill.py /path/to/skill-folder
    python gather_skill.py /path/to/skill-folder --output report.txt
"""

import argparse
import os
import sys
from pathlib import Path

# Security limits
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB per file
MAX_TOTAL_SIZE = 100 * 1024 * 1024  # 100 MB total
MAX_FILES = 1000  # Maximum number of files to process

# File extensions to read as text
TEXT_EXTENSIONS = {
    '.md', '.txt', '.py', '.sh', '.bash', '.js', '.ts', '.json', '.yaml', '.yml',
    '.html', '.css', '.xml', '.toml', '.ini', '.cfg', '.conf', '.sql', '.r', '.R',
    '.jsx', '.tsx', '.vue', '.svelte', '.php', '.rb', '.pl', '.lua', '.go', '.rs',
    '.java', '.kt', '.scala', '.c', '.cpp', '.h', '.hpp', '.cs', '.swift', '.m',
}

# Binary extensions that are generally safe (assets)
SAFE_BINARY_EXTENSIONS = {
    '.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg', '.ico', '.bmp',
    '.ttf', '.otf', '.woff', '.woff2', '.eot',
    '.pdf',
    '.zip', '.tar', '.gz', '.bz2', '.7z',
}

# Suspicious binary extensions
SUSPICIOUS_BINARY_EXTENSIONS = {
    '.exe', '.dll', '.so', '.dylib', '.bin', '.dat',
    '.pyc', '.pyo', '.class', '.jar', '.war',
    '.wasm', '.node',
}

def classify_file(filepath: Path) -> str:
    """Classify a file as text, safe-binary, suspicious-binary, or unknown."""
    ext = filepath.suffix.lower()
    if ext in TEXT_EXTENSIONS:
        return 'text'
    elif ext in SAFE_BINARY_EXTENSIONS:
        return 'safe-binary'
    elif ext in SUSPICIOUS_BINARY_EXTENSIONS:
        return 'suspicious-binary'
    else:
        # Try to detect if it's text
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                f.read(1024)
            return 'text'
        except (UnicodeDecodeError, IOError):
            return 'unknown-binary'

def gather_skill(skill_path: Path) -> dict:
    """Gather all files in a skill directory."""
    result = {
        'skill_path': str(skill_path),
        'files': [],
        'warnings': [],
    }
    
    if not skill_path.exists():
        result['warnings'].append(f"Path does not exist: {skill_path}")
        return result
    
    if not skill_path.is_dir():
        result['warnings'].append(f"Path is not a directory: {skill_path}")
        return result
    
    # Resolve the skill path for later containment checks
    skill_path_resolved = skill_path.resolve()
    
    # Check for SKILL.md
    skill_md = skill_path / 'SKILL.md'
    if not skill_md.exists():
        result['warnings'].append("SKILL.md not found - may not be a valid skill")
    
    # Track totals for resource limits
    total_size = 0
    file_count = 0
    
    # Walk the directory
    for root, dirs, files in os.walk(skill_path):
        # Skip hidden directories and symlinked directories
        filtered_dirs = []
        for d in dirs:
            dir_path = Path(root) / d
            if d.startswith('.'):
                continue
            if dir_path.is_symlink():
                result['warnings'].append(f"Skipping symlinked directory: {dir_path.relative_to(skill_path)}")
                continue
            filtered_dirs.append(d)
        dirs[:] = filtered_dirs
        
        for filename in files:
            if filename.startswith('.'):
                continue
            
            # Check file count limit
            file_count += 1
            if file_count > MAX_FILES:
                result['warnings'].append(f"File limit exceeded ({MAX_FILES}). Stopping enumeration.")
                return result
                
            filepath = Path(root) / filename
            rel_path = filepath.relative_to(skill_path)
            
            # Security check: Skip symlinks
            if filepath.is_symlink():
                result['warnings'].append(f"Skipping symlink: {rel_path}")
                continue
            
            # Security check: Verify file is within skill directory (no path escape)
            try:
                filepath_resolved = filepath.resolve()
                filepath_resolved.relative_to(skill_path_resolved)
            except ValueError:
                result['warnings'].append(f"Path escape attempt blocked: {rel_path}")
                continue
            
            file_size = filepath.stat().st_size
            
            file_info = {
                'path': str(rel_path),
                'absolute_path': str(filepath),
                'size': file_size,
                'type': classify_file(filepath),
                'content': None,
            }
            
            if file_info['type'] == 'text':
                # Check individual file size limit
                if file_size > MAX_FILE_SIZE:
                    file_info['content'] = f"[FILE TOO LARGE: {file_size:,} bytes, limit is {MAX_FILE_SIZE:,}]"
                    result['warnings'].append(f"File exceeds size limit: {rel_path} ({file_size:,} bytes)")
                # Check total size limit
                elif total_size + file_size > MAX_TOTAL_SIZE:
                    file_info['content'] = f"[SKIPPED: Total size limit ({MAX_TOTAL_SIZE:,} bytes) would be exceeded]"
                    result['warnings'].append(f"Total size limit reached, skipping: {rel_path}")
                else:
                    try:
                        with open(filepath, 'r', encoding='utf-8') as f:
                            file_info['content'] = f.read()
                        total_size += file_size
                    except Exception as e:
                        file_info['content'] = f"[Error reading file: {e}]"
                        result['warnings'].append(f"Could not read {rel_path}: {e}")
            
            elif file_info['type'] == 'suspicious-binary':
                result['warnings'].append(f"Suspicious binary file: {rel_path}")
                file_info['content'] = "[BINARY FILE - REQUIRES MANUAL INSPECTION]"
            
            elif file_info['type'] == 'unknown-binary':
                result['warnings'].append(f"Unknown binary file: {rel_path}")
                file_info['content'] = "[BINARY FILE - TYPE UNKNOWN]"
            
            else:  # safe-binary
                file_info['content'] = f"[BINARY ASSET: {filepath.suffix}]"
            
            result['files'].append(file_info)
    
    # Add summary info
    result['total_size'] = total_size
    result['file_count'] = file_count
    
    return result

def format_output(result: dict) -> str:
    """Format gathered skill data for review."""
    lines = []
    
    lines.append("=" * 80)
    lines.append("SKILL SECURITY REVIEW - FILE CONTENTS")
    lines.append("=" * 80)
    lines.append(f"\nSkill Path: {result['skill_path']}")
    lines.append(f"Total Files: {result.get('file_count', len(result['files']))}")
    lines.append(f"Total Size: {result.get('total_size', 0):,} bytes")
    lines.append(f"Limits: {MAX_FILES} files, {MAX_FILE_SIZE:,} bytes/file, {MAX_TOTAL_SIZE:,} bytes total")
    
    if result['warnings']:
        lines.append("\n### WARNINGS ###")
        for warning in result['warnings']:
            lines.append(f"  ⚠️  {warning}")
    
    lines.append("\n" + "-" * 80)
    lines.append("FILE INVENTORY")
    lines.append("-" * 80)
    
    for f in result['files']:
        type_indicator = {
            'text': '📄',
            'safe-binary': '🖼️',
            'suspicious-binary': '⚠️',
            'unknown-binary': '❓',
        }.get(f['type'], '?')
        lines.append(f"  {type_indicator} {f['path']} ({f['size']} bytes) [{f['type']}]")
    
    lines.append("\n" + "=" * 80)
    lines.append("FILE CONTENTS")
    lines.append("=" * 80)
    
    for f in result['files']:
        lines.append(f"\n{'#' * 80}")
        lines.append(f"# FILE: {f['path']}")
        lines.append(f"# TYPE: {f['type']}")
        lines.append(f"# SIZE: {f['size']} bytes")
        lines.append('#' * 80)
        
        if f['content']:
            lines.append(f['content'])
        else:
            lines.append("[No content available]")
    
    lines.append("\n" + "=" * 80)
    lines.append("END OF SKILL CONTENTS")
    lines.append("=" * 80)
    
    return '\n'.join(lines)

def main():
    parser = argparse.ArgumentParser(
        description='Gather skill files for security review'
    )
    parser.add_argument('skill_path', help='Path to the skill directory')
    parser.add_argument('--output', '-o', help='Output file (default: stdout)')
    
    args = parser.parse_args()
    
    skill_path = Path(args.skill_path).resolve()
    result = gather_skill(skill_path)
    output = format_output(result)
    
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(output)
        print(f"Output written to: {args.output}")
    else:
        print(output)

if __name__ == '__main__':
    main()
