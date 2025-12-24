"""
File Collector - File Integrity Monitoring
"""

import os
import hashlib
import re
from pathlib import Path
from typing import Dict, Any, List, Set, Optional
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent

from lonewarrior.collectors.base import BaseCollector
from lonewarrior.storage.models import Event, EventType
from lonewarrior.core.event_bus import EventPriority


# Webshell signatures (basic patterns)
WEBSHELL_PATTERNS = [
    rb'eval\s*\(\s*\$_(?:POST|GET|REQUEST)',
    rb'system\s*\(\s*\$_(?:POST|GET|REQUEST)',
    rb'exec\s*\(\s*\$_(?:POST|GET|REQUEST)',
    rb'passthru\s*\(\s*\$_(?:POST|GET|REQUEST)',
    rb'shell_exec\s*\(\s*\$_(?:POST|GET|REQUEST)',
    rb'base64_decode\s*\(\s*[\'"][\w+/=]{100,}',
    rb'<\?php\s+@eval',
    rb'c99shell',
    rb'r57shell',
    rb'WSO\s+shell',
]


class FileEventHandler(FileSystemEventHandler):
    """Handles file system events from watch dog"""
    
    def __init__(self, collector):
        self.collector = collector
        super().__init__()
    
    def on_modified(self, event):
        if not event.is_directory:
            self.collector.handle_file_change(event.src_path, 'modified')
    
    def on_created(self, event):
        if not event.is_directory:
            self.collector.handle_file_change(event.src_path, 'created')


class FileCollector(BaseCollector):
    """File Integrity Monitoring collector"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        self.watch_paths = self.config['file_integrity']['watch_paths']
        self.exclude_patterns = self.config['file_integrity']['exclude_patterns']
        self.webshell_detection = self.config['file_integrity']['webshell_detection']
        
        # File hash cache
        self.file_hashes: Dict[str, str] = {}
        
        # Watchdog observer
        self.observer = Observer()
        self.event_handler = FileEventHandler(self)
        
        # Initial baseline
        self._compute_initial_hashes()
    
    def _get_collection_interval(self) -> int:
        return self.config['collection']['file_integrity_interval']
    
    def _compute_initial_hashes(self):
        """Compute hashes for all watched files"""
        self.logger.info("Computing initial file hashes...")
        count = 0
        
        for watch_path in self.watch_paths:
            expanded_path = os.path.expanduser(os.path.expandvars(watch_path))
            
            # Handle wildcards
            if '*' in expanded_path:
                parent = str(Path(expanded_path).parent)
                pattern = Path(expanded_path).name
                
                if os.path.exists(parent):
                    for item in Path(parent).iterdir():
                        if item.is_dir() and self._matches_pattern(str(item), pattern):
                            count += self._hash_directory(str(item))
            elif os.path.exists(expanded_path):
                if os.path.isdir(expanded_path):
                    count += self._hash_directory(expanded_path)
                else:
                    self._hash_file(expanded_path)
                    count += 1
        
        self.logger.info(f"Computed hashes for {count} files")
    
    def _matches_pattern(self, path: str, pattern: str) -> bool:
        """Check if path matches glob pattern"""
        import fnmatch
        return fnmatch.fnmatch(os.path.basename(path), pattern)
    
    def _hash_directory(self, dir_path: str) -> int:
        """Recursively hash all files in directory"""
        count = 0
        try:
            for root, dirs, files in os.walk(dir_path):
                for filename in files:
                    if self._should_exclude(filename):
                        continue
                    
                    filepath = os.path.join(root, filename)
                    self._hash_file(filepath)
                    count += 1
        except PermissionError:
            pass
        
        return count
    
    def _should_exclude(self, filename: str) -> bool:
        """Check if file should be excluded"""
        import fnmatch
        for pattern in self.exclude_patterns:
            if fnmatch.fnmatch(filename, pattern):
                return True
        return False
    
    def _hash_file(self, filepath: str) -> Optional[str]:
        """Compute SHA256 hash of file"""
        try:
            sha256 = hashlib.sha256()
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    sha256.update(chunk)
            
            file_hash = sha256.hexdigest()
            self.file_hashes[filepath] = file_hash
            return file_hash
        except (PermissionError, FileNotFoundError, IsADirectoryError):
            return None
    
    def start(self):
        """Start file monitoring"""
        super().start()
        
        # Start watchdog observer
        for watch_path in self.watch_paths:
            expanded = os.path.expanduser(os.path.expandvars(watch_path))
            
            # Skip wildcards for watchdog (we scan those manually)
            if '*' in expanded:
                continue
            
            if os.path.exists(expanded) and os.path.isdir(expanded):
                self.observer.schedule(self.event_handler, expanded, recursive=True)
                self.logger.info(f"Watching: {expanded}")
        
        self.observer.start()
    
    def stop(self):
        """Stop file monitoring"""
        self.observer.stop()
        self.observer.join(timeout=5)
        super().stop()
    
    def collect(self):
        """Periodic file integrity check"""
        # Re-scan all files and compare hashes
        for filepath, old_hash in list(self.file_hashes.items()):
            if not os.path.exists(filepath):
                # File deleted
                self.logger.warning(f"File deleted: {filepath}")
                self.file_hashes.pop(filepath, None)
                continue
            
            new_hash = self._hash_file(filepath)
            if new_hash and new_hash != old_hash:
                self.handle_file_change(filepath, 'modified')
    
    def handle_file_change(self, filepath: str, change_type: str):
        """Handle file modification or creation"""
        if self._should_exclude(os.path.basename(filepath)):
            return
        
        new_hash = self._hash_file(filepath)
        if not new_hash:
            return
        
        old_hash = self.file_hashes.get(filepath)
        
        # Detect webshells
        is_webshell = False
        if self.webshell_detection and filepath.endswith(('.php', '.jsp', '.asp', '.aspx')):
            is_webshell = self._detect_webshell(filepath)
        
        event_data = {
            'filepath': filepath,
            'change_type': change_type,
            'old_hash': old_hash,
            'new_hash': new_hash,
            'is_webshell': is_webshell,
            'filesize': os.path.getsize(filepath),
        }
        
        # Update cache
        self.file_hashes[filepath] = new_hash
        
        event = Event(
            event_type=EventType.FILE_MODIFIED.value if change_type == 'modified' else EventType.FILE_CREATED.value,
            source=self.__class__.__name__,
            data=event_data,
            baseline_phase=self.state.get_current_phase().value
        )
        
        event.id = self.db.insert_event(event)
        
        # High priority if webshell detected
        priority = EventPriority.CRITICAL if is_webshell else EventPriority.HIGH
        
        self.publish_event(
            event.event_type,
            event_data,
            priority
        )
        
        if is_webshell:
            self.logger.critical(f"🚨 WEBSHELL DETECTED: {filepath}")
        else:
            self.logger.warning(f"File {change_type}: {filepath}")
    
    def _detect_webshell(self, filepath: str) -> bool:
        """Detect webshell signatures in file"""
        try:
            with open(filepath, 'rb') as f:
                content = f.read(1024 * 1024)  # Read first 1MB
            
            for pattern in WEBSHELL_PATTERNS:
                if re.search(pattern, content, re.IGNORECASE):
                    return True
            
            return False
        except:
            return False
