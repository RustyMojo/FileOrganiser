import os
import re
import logging
import mimetypes
import collections
import hashlib
import magic
import exifread
import chardet
import filetype
import datetime
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
import seaborn as sns
from PIL import Image
import docx2txt
import PyPDF2
import multiprocessing
from pathlib import Path
from datetime import datetime
from tqdm import tqdm
import pickle
import json
from typing import Dict, List, Tuple, Any, Optional, Union, Set
from rule import Rule

class FileAnalyzer:
    """Advanced file analyzer to discover patterns and suggest sophisticated organisation rules"""
    
    def __init__(self, cache_dir=None):
        # Core analysis counters
        self.file_types = collections.defaultdict(int)
        self.mime_types = collections.defaultdict(int)
        self.extensions = collections.defaultdict(int)
        self.name_patterns = collections.defaultdict(int)
        self.date_patterns = collections.defaultdict(int)
        self.size_categories = collections.defaultdict(int)
        self.common_prefixes = collections.defaultdict(int)
        self.common_suffixes = collections.defaultdict(int)
        self.modification_times = collections.defaultdict(int)
        self.access_times = collections.defaultdict(int)
        self.creation_times = collections.defaultdict(int)
        
        # Advanced analysis
        self.duplicate_files = collections.defaultdict(list)
        self.content_clusters = {}
        self.naming_inconsistencies = []
        self.potentially_sensitive_files = []
        self.orphaned_files = []
        self.corrupted_files = []
        self.unusual_permissions = []
        
        # File content specifics
        self.image_metadata = {}
        self.document_metadata = {}
        self.media_metadata = {}
        self.code_statistics = {}
        
        # Usage patterns
        self.least_accessed_files = []
        self.most_accessed_files = []
        self.usage_frequency = {}
        
        # Analysis results
        self.analyzed_files = []
        self.skipped_files = []
        self.analysis_summary = {}
        
        # Cache mechanism
        self.cache_dir = cache_dir
        if self.cache_dir and not os.path.exists(self.cache_dir):
            os.makedirs(self.cache_dir)
        self.cache = {}
        
        # Initialize mime types
        mimetypes.init()
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger("FileAnalyzer")
        
    def analyze_directory(self, directory_path, max_files=10000, 
                          depth=None, follow_symlinks=False, 
                          exclude_patterns=None, include_patterns=None,
                          detect_duplicates=True, extract_metadata=True,
                          generate_visualizations=True):
        """Analyze files in a directory and generate comprehensive insights
        
        Args:
            directory_path (str): Path to directory to analyze
            max_files (int): Maximum number of files to analyze
            depth (Optional[int]): Maximum directory depth to traverse
            follow_symlinks (bool): Whether to follow symbolic links
            exclude_patterns (Optional[List[str]]): Patterns of files/dirs to exclude
            include_patterns (Optional[List[str]]): Patterns of files/dirs to specifically include
            detect_duplicates (bool): Perform duplicate detection
            extract_metadata (bool): Extract detailed metadata from supported file types
            generate_visualizations (bool): Generate charts and visualizations
            
        Returns:
            Dict[str, Any]: Analysis results as a structured dictionary
        """
        start_time = datetime.now()
        self.logger.info(f"Starting analysis of {directory_path}")
        
        if not os.path.exists(directory_path) or not os.path.isdir(directory_path):
            self.logger.error(f"Invalid directory: {directory_path}")
            return {"error": "Invalid directory"}
            
        # Reset analysis data
        self._reset_analysis_data()
        
        # Load cache if available
        self._load_cache()
        
        # Collect all files with filtering
        all_files = self._collect_files(
            directory_path, 
            max_files, 
            depth, 
            follow_symlinks, 
            exclude_patterns, 
            include_patterns
        )
        
        if not all_files:
            self.logger.warning(f"No files found in {directory_path} matching criteria")
            return {"error": "No files found matching criteria"}
        
        # Use multiprocessing for basic file analysis
        self.logger.info(f"Analyzing {len(all_files)} files with {multiprocessing.cpu_count()} processes")
        with multiprocessing.Pool(processes=max(1, multiprocessing.cpu_count() - 1)) as pool:
            results = list(tqdm(
                pool.imap(self._analyze_file_wrapper, [(file, extract_metadata) for file in all_files]),
                total=len(all_files),
                desc="Analyzing files"
            ))
        
        # Process results
        self._process_analysis_results(results)
        
        # Perform additional analyses
        if detect_duplicates:
            self._detect_duplicate_files(all_files)
        
        if extract_metadata:
            self._analyze_content_clusters(all_files)
            self._detect_naming_inconsistencies()
            self._identify_potential_issues(all_files)
        
        # Generate visualizations if requested
        if generate_visualizations:
            visualization_path = self._generate_visualizations(directory_path)
            self.analysis_summary['visualization_path'] = visualization_path
        
        # Generate report
        report_text = self._generate_report(directory_path)
        self.analysis_summary['report_text'] = report_text
        self.analysis_summary['suggested_rules'] = self._suggest_rules(directory_path)
        self.analysis_summary['analyzed_file_count'] = len(self.analyzed_files)
        self.analysis_summary['skipped_file_count'] = len(self.skipped_files)
        self.analysis_summary['analysis_duration'] = str(datetime.now() - start_time)
        
        # Save cache
        self._save_cache()
        
        self.logger.info(f"Analysis completed in {datetime.now() - start_time}")
        return self.analysis_summary
    
    def _reset_analysis_data(self):
        """Reset all analysis data structures"""
        # Reset counters
        self.file_types.clear()
        self.mime_types.clear()
        self.extensions.clear()
        self.name_patterns.clear()
        self.date_patterns.clear()
        self.size_categories.clear()
        self.common_prefixes.clear()
        self.common_suffixes.clear()
        self.modification_times.clear()
        self.access_times.clear()
        self.creation_times.clear()
        
        # Reset advanced analysis
        self.duplicate_files.clear()
        self.content_clusters.clear()
        self.naming_inconsistencies = []
        self.potentially_sensitive_files = []
        self.orphaned_files = []
        self.corrupted_files = []
        self.unusual_permissions = []
        
        # Reset file content specifics
        self.image_metadata = {}
        self.document_metadata = {}
        self.media_metadata = {}
        self.code_statistics = {}
        
        # Reset usage patterns
        self.least_accessed_files = []
        self.most_accessed_files = []
        self.usage_frequency = {}
        
        # Reset analysis results
        self.analyzed_files = []
        self.skipped_files = []
        self.analysis_summary = {}
    
    def _collect_files(self, directory_path, max_files, depth, 
                      follow_symlinks, exclude_patterns, include_patterns):
        """Collect files matching the specified criteria"""
        all_files = []
        skipped_count = 0
        
        # Compile regex patterns if provided
        exclude_regex = None
        include_regex = None
        
        if exclude_patterns:
            exclude_regex = re.compile('|'.join(exclude_patterns))
        if include_patterns:
            include_regex = re.compile('|'.join(include_patterns))
        
        for root, dirs, files in os.walk(directory_path, topdown=True):
            # Apply depth limit if specified
            if depth is not None:
                current_depth = root[len(directory_path):].count(os.sep)
                if current_depth >= depth:
                    dirs[:] = []  # Prevent further recursion
            
            # Skip excluded directories
            if exclude_regex:
                dirs[:] = [d for d in dirs if not exclude_regex.search(d) and 
                           (follow_symlinks or not os.path.islink(os.path.join(root, d)))]
            
            # Process files
            for file in files:
                file_path = os.path.join(root, file)
                
                # Skip symlinks if not following them
                if not follow_symlinks and os.path.islink(file_path):
                    self.skipped_files.append((file_path, "symlink"))
                    skipped_count += 1
                    continue
                
                # Apply exclusion pattern
                if exclude_regex and exclude_regex.search(file):
                    self.skipped_files.append((file_path, "excluded"))
                    skipped_count += 1
                    continue
                
                # Apply inclusion pattern if specified
                if include_regex and not include_regex.search(file):
                    self.skipped_files.append((file_path, "not included"))
                    skipped_count += 1
                    continue
                
                all_files.append(file_path)
                if len(all_files) >= max_files:
                    self.logger.info(f"Reached max files limit ({max_files})")
                    break
            
            if len(all_files) >= max_files:
                break
        
        self.logger.info(f"Collected {len(all_files)} files, skipped {skipped_count}")
        return all_files
    
    def _analyze_file_wrapper(self, args):
        """Wrapper for _analyze_file to use with multiprocessing"""
        file_path, extract_metadata = args
        return self._analyze_file(file_path, extract_metadata)
    
    def _analyze_file(self, file_path, extract_metadata=True):
        """Analyze a single file and return comprehensive insights
        
        Returns:
            dict: Dictionary containing analysis results
        """
        try:
            # Check if we have cached results
            cache_key = f"{file_path}_{os.path.getmtime(file_path)}"
            if cache_key in self.cache:
                return self.cache[cache_key]
            
            result = {
                'file_path': file_path,
                'exists': os.path.exists(file_path),
                'is_file': os.path.isfile(file_path),
                'is_dir': os.path.isdir(file_path),
                'is_symlink': os.path.islink(file_path),
            }
            
            if not result['exists'] or not result['is_file']:
                return result
            
            # Basic file information
            file_name = os.path.basename(file_path)
            file_ext = os.path.splitext(file_name)[1].lower()
            file_size = os.path.getsize(file_path)
            
            result.update({
                'file_name': file_name,
                'file_extension': file_ext,
                'file_size': file_size,
                'file_size_formatted': self._format_size(file_size),
                'parent_directory': os.path.dirname(file_path),
            })
            
            # Get file timestamps
            file_stat = os.stat(file_path)
            result['modification_time'] = datetime.fromtimestamp(file_stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
            result['access_time'] = datetime.fromtimestamp(file_stat.st_atime).strftime('%Y-%m-%d %H:%M:%S')
            
            try:
                if os.name == 'nt':  # Windows
                    result['creation_time'] = datetime.fromtimestamp(file_stat.st_ctime).strftime('%Y-%m-%d %H:%M:%S')
                else:  # Unix/Linux/Mac
                    try:
                        creation_time = file_stat.st_birthtime  # macOS
                        result['creation_time'] = datetime.fromtimestamp(creation_time).strftime('%Y-%m-%d %H:%M:%S')
                    except AttributeError:
                        # Fallback to modification time on Linux
                        result['creation_time'] = result['modification_time']
            except Exception as e:
                result['creation_time'] = "Unknown"
                result['creation_time_error'] = str(e)
            
            # File type detection
            try:
                # Try using libmagic for more accurate type detection
                mime_type = magic.Magic(mime=True).from_file(file_path)
                result['mime_type'] = mime_type
                
                # Alternative file type detection
                kind = filetype.guess(file_path)
                if kind is not None:
                    result['detected_mime'] = kind.mime
                    result['detected_extension'] = kind.extension
                
                # Fall back to mimetypes if needed
                if not mime_type:
                    mime_type, _ = mimetypes.guess_type(file_path)
                    result['mime_type'] = mime_type or "unknown"
                
                if mime_type:
                    main_type = mime_type.split('/')[0]
                    sub_type = mime_type.split('/')[1] if '/' in mime_type else ""
                    result['main_type'] = main_type
                    result['sub_type'] = sub_type
                else:
                    result['main_type'] = "unknown"
                    result['sub_type'] = "unknown"
                    
            except Exception as e:
                # Fallback to basic mimetype
                mime_type, _ = mimetypes.guess_type(file_path)
                result['mime_type'] = mime_type or "unknown"
                result['main_type'] = mime_type.split('/')[0] if mime_type else "unknown"
                result['sub_type'] = mime_type.split('/')[1] if mime_type and '/' in mime_type else "unknown"
                result['mime_detection_error'] = str(e)
            
            # File permissions and owner
            try:
                result['permissions'] = oct(file_stat.st_mode)[-3:]
                result['owner_uid'] = file_stat.st_uid
                result['group_gid'] = file_stat.st_gid
            except Exception as e:
                result['permissions_error'] = str(e)
            
            # Name pattern analysis
            result['name_patterns'] = []
            
            # Check for date patterns in name
            date_patterns = [
                (r'(\d{4}[-_/]?\d{2}[-_/]?\d{2})', "year_month_day"),
                (r'(\d{2}[-_/]?\d{2}[-_/]?\d{4})', "day_month_year"),
                (r'(\d{2}[-_/]?\d{2}[-_/]?\d{2})', "short_date")
            ]
            
            for pattern, pattern_name in date_patterns:
                if re.search(pattern, file_name):
                    result['name_patterns'].append(pattern_name)
                    
            # Check for numeric prefixes
            if re.match(r'^\d+[\s_-]', file_name):
                result['name_patterns'].append("numeric_prefix")
                
            # Check for version numbers
            if re.search(r'v\d+(\.\d+)*', file_name, re.IGNORECASE):
                result['name_patterns'].append("version_number")
                
            # Check for UUID/GUID
            if re.search(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', file_name, re.IGNORECASE):
                result['name_patterns'].append("uuid")
                
            # Extract common prefixes (3+ characters)
            name_without_ext = os.path.splitext(file_name)[0]
            if len(name_without_ext) >= 3:
                result['prefix'] = name_without_ext[:3].lower()
                result['suffix'] = name_without_ext[-3:].lower() if len(name_without_ext) >= 3 else ""
                
            # Determine size category
            if file_size < 1024:  # < 1 KB
                result['size_category'] = "minuscule"
            elif file_size < 10 * 1024:  # < 10 KB
                result['size_category'] = "tiny"
            elif file_size < 100 * 1024:  # < 100 KB
                result['size_category'] = "very_small"
            elif file_size < 1024 * 1024:  # < 1 MB
                result['size_category'] = "small"
            elif file_size < 10 * 1024 * 1024:  # < 10 MB
                result['size_category'] = "medium"
            elif file_size < 100 * 1024 * 1024:  # < 100 MB
                result['size_category'] = "large"
            elif file_size < 1024 * 1024 * 1024:  # < 1 GB
                result['size_category'] = "very_large"
            else:  # >= 1 GB
                result['size_category'] = "enormous"
                
            # Calculate file hash for duplicate detection
            try:
                if file_size < 100 * 1024 * 1024:  # Only hash files smaller than 100MB
                    with open(file_path, 'rb') as f:
                        # Use a faster hash for larger files
                        if file_size > 10 * 1024 * 1024:  # > 10MB
                            result['file_hash'] = hashlib.md5(f.read()).hexdigest()
                        else:
                            result['file_hash'] = hashlib.sha256(f.read()).hexdigest()
                else:
                    # For larger files, just hash the first and last MB
                    with open(file_path, 'rb') as f:
                        first_mb = f.read(1024 * 1024)
                        f.seek(-1024 * 1024, 2)  # Seek to 1MB before the end
                        last_mb = f.read(1024 * 1024)
                        result['file_hash'] = hashlib.md5(first_mb + last_mb).hexdigest()
                        result['hash_type'] = "partial"
            except Exception as e:
                result['hash_error'] = str(e)
            
            # Extract detailed metadata for specific file types
            if extract_metadata:
                try:
                    self._extract_file_metadata(file_path, result)
                except Exception as e:
                    result['metadata_extraction_error'] = str(e)
            
            # Check for potential issues
            if not os.access(file_path, os.R_OK):
                result['potential_issue'] = "not_readable"
            
            # Cache the result
            self.cache[cache_key] = result
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error analyzing file {file_path}: {e}")
            return {
                'file_path': file_path,
                'error': str(e),
                'traceback': logging.traceback.format_exc()
            }
    
    def _extract_file_metadata(self, file_path, result):
        """Extract metadata from different file types"""
        file_ext = result.get('file_extension', '').lower()
        mime_type = result.get('mime_type', '')
        
        # Image file metadata
        if result.get('main_type') == 'image':
            try:
                with open(file_path, 'rb') as img_file:
                    tags = exifread.process_file(img_file, details=False)
                    if tags:
                        exif_data = {}
                        for tag, value in tags.items():
                            exif_data[tag] = str(value)
                        result['exif_data'] = exif_data
                        
                        # Extract key EXIF information
                        if 'EXIF DateTimeOriginal' in exif_data:
                            result['capture_date'] = exif_data['EXIF DateTimeOriginal']
                        if 'EXIF Make' in exif_data:
                            result['camera_make'] = exif_data['EXIF Make']
                        if 'EXIF Model' in exif_data:
                            result['camera_model'] = exif_data['EXIF Model']
                        
                # Get image dimensions
                try:
                    with Image.open(file_path) as img:
                        width, height = img.size
                        result['image_width'] = width
                        result['image_height'] = height
                        result['image_format'] = img.format
                        result['image_mode'] = img.mode
                except Exception as e:
                    result['image_info_error'] = str(e)
                        
            except Exception as e:
                result['exif_error'] = str(e)
                
        # Document metadata
        elif file_ext in ['.pdf', '.PDF']:
            try:
                with open(file_path, 'rb') as pdf_file:
                    pdf_reader = PyPDF2.PdfReader(pdf_file)
                    result['pdf_pages'] = len(pdf_reader.pages)
                    
                    if pdf_reader.metadata:
                        result['pdf_metadata'] = {
                            'title': pdf_reader.metadata.get('/Title', ''),
                            'author': pdf_reader.metadata.get('/Author', ''),
                            'subject': pdf_reader.metadata.get('/Subject', ''),
                            'creator': pdf_reader.metadata.get('/Creator', ''),
                            'producer': pdf_reader.metadata.get('/Producer', ''),
                            'creation_date': pdf_reader.metadata.get('/CreationDate', '')
                        }
                    
                    # Get text from first page for content fingerprinting
                    try:
                        first_page = pdf_reader.pages[0]
                        text = first_page.extract_text()
                        result['content_sample'] = text[:500] if text else ""
                    except:
                        pass
            except Exception as e:
                result['pdf_error'] = str(e)
                
        elif file_ext in ['.doc', '.docx']:
            try:
                text = docx2txt.process(file_path)
                result['doc_text_length'] = len(text)
                result['content_sample'] = text[:500] if text else ""
            except Exception as e:
                result['docx_error'] = str(e)
                
        # Text files
        elif file_ext in ['.txt', '.csv', '.json', '.xml', '.html', '.md', '.log']:
            try:
                # Detect encoding
                with open(file_path, 'rb') as f:
                    raw_data = f.read(min(1024 * 1024, os.path.getsize(file_path)))  # Read up to 1MB
                    detection = chardet.detect(raw_data)
                    result['detected_encoding'] = detection['encoding']
                    result['encoding_confidence'] = detection['confidence']
                
                # Get line count and sample
                try:
                    encoding = detection['encoding'] or 'utf-8'
                    with open(file_path, 'r', encoding=encoding, errors='replace') as f:
                        lines = f.readlines()
                        result['line_count'] = len(lines)
                        result['content_sample'] = ''.join(lines[:10]).strip()[:500]
                except Exception as e:
                    result['text_reading_error'] = str(e)
            
            except Exception as e:
                result['text_analysis_error'] = str(e)
                
        # Programming language files
        elif file_ext in ['.py', '.js', '.java', '.c', '.cpp', '.cs', '.php', '.rb', '.go', '.rs', '.swift']:
            try:
                with open(file_path, 'rb') as f:
                    raw_data = f.read(min(1024 * 1024, os.path.getsize(file_path)))
                    detection = chardet.detect(raw_data)
                
                encoding = detection['encoding'] or 'utf-8'
                with open(file_path, 'r', encoding=encoding, errors='replace') as f:
                    lines = f.readlines()
                    result['line_count'] = len(lines)
                    
                    # Count non-empty lines
                    non_empty = sum(1 for line in lines if line.strip())
                    result['non_empty_lines'] = non_empty
                    
                    # Count comment lines (simplified)
                    comment_markers = {
                        '.py': ['#'],
                        '.js': ['//', '/*'],
                        '.java': ['//', '/*'],
                        '.c': ['//', '/*'],
                        '.cpp': ['//', '/*'],
                        '.cs': ['//', '/*'],
                        '.php': ['//', '#', '/*'],
                        '.rb': ['#'],
                        '.go': ['//', '/*'],
                        '.rs': ['//', '/*'],
                        '.swift': ['//', '/*']
                    }
                    
                    markers = comment_markers.get(file_ext, ['#', '//'])
                    comment_lines = sum(1 for line in lines if any(line.strip().startswith(m) for m in markers))
                    result['comment_lines'] = comment_lines
                    
                    # Calculate code to comment ratio
                    if comment_lines > 0:
                        result['code_to_comment_ratio'] = (non_empty - comment_lines) / comment_lines
                    
                    # Sample content
                    result['content_sample'] = ''.join(lines[:20]).strip()[:500]
            
            except Exception as e:
                result['code_analysis_error'] = str(e)
        
        return result
    
    def _process_analysis_results(self, results):
        """Process the results from file analysis"""
        for result in results:
            # Skip entries with errors
            if 'error' in result:
                self.skipped_files.append((result.get('file_path', 'unknown'), result['error']))
                continue
                
            # Track this file as successfully analyzed
            self.analyzed_files.append(result.get('file_path'))
                
            # Collect statistics
            if 'main_type' in result:
                self.file_types[result['main_type']] += 1
                
            if 'mime_type' in result:
                self.mime_types[result['mime_type']] += 1
                
            if 'file_extension' in result:
                ext = result['file_extension'].lower()
                if ext:
                    self.extensions[ext] += 1
            
            # Name patterns
            if 'name_patterns' in result and result['name_patterns']:
                for pattern in result['name_patterns']:
                    self.name_patterns[pattern] += 1
            
            # Date patterns from file dates
            if 'creation_time' in result and result['creation_time'] != "Unknown":
                try:
                    creation_date = datetime.strptime(result['creation_time'], '%Y-%m-%d %H:%M:%S')
                    year = creation_date.year
                    month = creation_date.month
                    quarter = (month - 1) // 3 + 1
                    
                    self.date_patterns[f"year_{year}"] += 1
                    self.date_patterns[f"month_{year}_{month}"] += 1
                    self.date_patterns[f"quarter_{year}_Q{quarter}"] += 1
                    
                    # Group by creation time periods
                    self.creation_times[year] += 1
                except Exception as e:
                    self.logger.debug(f"Error parsing creation time: {e}")
            
            # Group by modification time
            if 'modification_time' in result:
                try:
                    mod_date = datetime.strptime(result['modification_time'], '%Y-%m-%d %H:%M:%S')
                    self.modification_times[mod_date.year] += 1
                except Exception:
                    pass
            
            # Group by access time
            if 'access_time' in result:
                try:
                    access_date = datetime.strptime(result['access_time'], '%Y-%m-%d %H:%M:%S')
                    self.access_times[access_date.year] += 1
                except Exception:
                    pass
            
            # Size categories
            if 'size_category' in result:
                self.size_categories[result['size_category']] += 1
            
            # Prefix and suffix analysis
            if 'prefix' in result and result['prefix']:
                self.common_prefixes[result['prefix']] += 1
                
            if 'suffix' in result and result['suffix']:
                self.common_suffixes[result['suffix']] += 1
    
    def _detect_duplicate_files(self, file_paths):
        """Detect duplicate files based on hash values"""
        self.logger.info("Detecting duplicate files")
        hash_to_files = {}
        
        # Group files by hash
        for result in self.cache.values():
            if 'file_hash' in result and 'file_path' in result:
                file_hash = result['file_hash']
                file_path = result['file_path']
                
                if file_hash not in hash_to_files:
                    hash_to_files[file_hash] = []
                    
                hash_to_files[file_hash].append({
                    'path': file_path,
                    'size': result.get('file_size', 0),
                    'name': result.get('file_name', os.path.basename(file_path))
                })
        
        # Filter for hashes with multiple files
        for file_hash, files in hash_to_files.items():
            if len(files) > 1:
                self.duplicate_files[file_hash] = files
                
        self.logger.info(f"Found {len(self.duplicate_files)} groups of duplicate files")
    
    def _analyze_content_clusters(self, file_paths):
        """Group files by content similarity or type"""
        # Group by mime type and extension
        content_type_groups = collections.defaultdict(list)
        
        for result in self.cache.values():
            if 'main_type' in result and 'sub_type' in result and 'file_path' in result:
                content_type = f"{result['main_type']}/{result['sub_type']}"
                content_type_groups[content_type].append(result['file_path'])
        
        # Keep only groups with multiple files
        self.content_clusters = {k: v for k, v in content_type_groups.items() if len(v) > 1}