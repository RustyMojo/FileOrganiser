import os
import re
import logging
import mimetypes
import collections
from datetime import datetime
from pathlib import Path
import multiprocessing
from rule import Rule

class FileAnalyzer:
    """AI-like file analyzer to discover patterns and suggest organisation rules"""
    
    def __init__(self):
        self.file_types = collections.defaultdict(int)
        self.name_patterns = collections.defaultdict(int)
        self.date_patterns = collections.defaultdict(int)
        self.size_categories = collections.defaultdict(int)
        self.common_prefixes = collections.defaultdict(int)
        
        # Initialize mime types
        mimetypes.init()
        
    def analyze_directory(self, directory_path, max_files=1000):
        """Analyze files in a directory and generate insights
        
        Args:
            directory_path (str): Path to directory to analyze
            max_files (int): Maximum number of files to analyze
            
        Returns:
            str: Analysis results
        """
        if not os.path.exists(directory_path) or not os.path.isdir(directory_path):
            logging.error(f"Invalid directory: {directory_path}")
            return "Invalid directory"
            
        # Reset counters
        self.file_types.clear()
        self.name_patterns.clear()
        self.date_patterns.clear()
        self.size_categories.clear()
        self.common_prefixes.clear()
        
        # Collect all files
        all_files = []
        for root, _, files in os.walk(directory_path):
            for file in files:
                all_files.append(os.path.join(root, file))
                if len(all_files) >= max_files:
                    break
            if len(all_files) >= max_files:
                break
                
        # Use multiprocessing to analyze files
        with multiprocessing.Pool(processes=max(1, multiprocessing.cpu_count() - 1)) as pool:
            results = pool.map(self._analyze_file, all_files)
            
        # Process results
        for file_type, name_pattern, date_pattern, size_category, prefix in results:
            if file_type:
                self.file_types[file_type] += 1
            if name_pattern:
                self.name_patterns[name_pattern] += 1
            if date_pattern:
                self.date_patterns[date_pattern] += 1
            if size_category:
                self.size_categories[size_category] += 1
            if prefix:
                self.common_prefixes[prefix] += 1
                
        # Generate insights and suggestions
        return self._generate_report(directory_path)
    
    def _analyze_file(self, file_path):
        """Analyze a single file and return insights
        
        Returns:
            tuple: (file_type, name_pattern, date_pattern, size_category, prefix)
        """
        try:
            file_name = os.path.basename(file_path)
            file_ext = os.path.splitext(file_name)[1].lower()
            file_size = os.path.getsize(file_path)
            
            # Get file type
            mime_type, _ = mimetypes.guess_type(file_path)
            if mime_type:
                main_type = mime_type.split('/')[0]
                file_type = main_type
            else:
                file_type = "unknown"
                
            # Extract name patterns
            name_pattern = None
            # Check for date patterns in name
            date_match = re.search(r'(\d{4}[-_]?\d{2}[-_]?\d{2})|(\d{2}[-_]?\d{2}[-_]?\d{4})', file_name)
            if date_match:
                name_pattern = "date_in_name"
                
            # Check for numeric prefixes
            if re.match(r'^\d+[\s_-]', file_name):
                name_pattern = "numeric_prefix"
                
            # Extract common prefixes (3+ characters)
            prefix = None
            name_without_ext = os.path.splitext(file_name)[0]
            if len(name_without_ext) >= 3:
                prefix = name_without_ext[:3].lower()
                
            # Determine date pattern
            date_pattern = None
            try:
                # Get file creation/modification time
                if os.name == 'nt':  # Windows
                    creation_time = os.path.getctime(file_path)
                else:  # Unix/Linux/Mac
                    stat = os.stat(file_path)
                    try:
                        creation_time = stat.st_birthtime  # macOS
                    except AttributeError:
                        # Fallback to modification time on Linux
                        creation_time = stat.st_mtime
                        
                file_date = datetime.fromtimestamp(creation_time)
                
                # Check which year/month/quarter the file belongs to
                year = file_date.year
                month = file_date.month
                quarter = (month - 1) // 3 + 1
                
                date_pattern = f"year_{year}"
                
            except Exception as e:
                logging.debug(f"Error getting file date for {file_path}: {e}")
                
            # Determine size category
            size_category = None
            if file_size < 10 * 1024:  # < 10 KB
                size_category = "tiny"
            elif file_size < 1024 * 1024:  # < 1 MB
                size_category = "small"
            elif file_size < 10 * 1024 * 1024:  # < 10 MB
                size_category = "medium"
            elif file_size < 100 * 1024 * 1024:  # < 100 MB
                size_category = "large"
            else:  # >= 100 MB
                size_category = "very_large"
                
            return file_type, name_pattern, date_pattern, size_category, prefix
            
        except Exception as e:
            logging.error(f"Error analyzing file {file_path}: {e}")
            return None, None, None, None, None
    
    def _generate_report(self, directory_path):
        """Generate a report based on analysis results
        
        Returns:
            str: Formatted report text
        """
        total_files = sum(self.file_types.values())
        if total_files == 0:
            return "No files were analyzed."
            
        report = []
        report.append(f"=== File Analysis Report ===")
        report.append(f"Directory: {directory_path}")
        report.append(f"Files analyzed: {total_files}\n")
        
        # File type distribution
        report.append("== File Type Distribution ==")
        sorted_types = sorted(self.file_types.items(), key=lambda x: x[1], reverse=True)
        for file_type, count in sorted_types[:10]:  # Top 10
            percentage = (count / total_files) * 100
            report.append(f"{file_type}: {count} files ({percentage:.1f}%)")
        report.append("")
        
        # Size categories
        report.append("== File Size Distribution ==")
        sorted_sizes = sorted(self.size_categories.items(), key=lambda x: x[1], reverse=True)
        for size_cat, count in sorted_sizes:
            percentage = (count / total_files) * 100
            report.append(f"{size_cat}: {count} files ({percentage:.1f}%)")
        report.append("")
        
        # Generate rule suggestions
        report.append("== Suggested organisation Rules ==")
        rules = self._suggest_rules(directory_path)
        
        if not rules:
            report.append("No rule suggestions available for this directory.")
        else:
            for i, rule in enumerate(rules, 1):
                report.append(f"{i}. {rule.name}")
                report.append(f"   Criteria: {rule.criteria} {rule.rule_type} {rule.value}")
                report.append(f"   Destination: {rule.destination}")
                report.append("")
        
        return "\n".join(report)
    
    def _suggest_rules(self, base_directory):
        """Suggest organisation rules based on analysis
        
        Returns:
            list: List of Rule objects
        """
        rules = []
        
        # Get parent directory path for destination suggestions
        parent_dir = os.path.dirname(base_directory.rstrip('/\\'))
        
        # Rule 1: organise by file type if there are multiple types
        if len(self.file_types) > 1:
            for file_type, count in sorted(self.file_types.items(), key=lambda x: x[1], reverse=True):
                if count >= 3:  # Only suggest for types with at least 3 files
                    if file_type == "image":
                        rule = Rule(
                            name=f"Images organisation",
                            criteria="Content Type",
                            rule_type="Contains",
                            value="image/",
                            destination=os.path.join(parent_dir, "Images")
                        )
                        rules.append(rule)
                    elif file_type == "audio":
                        rule = Rule(
                            name=f"Audio organisation",
                            criteria="Content Type",
                            rule_type="Contains",
                            value="audio/",
                            destination=os.path.join(parent_dir, "Audio")
                        )
                        rules.append(rule)
                    elif file_type == "video":
                        rule = Rule(
                            name=f"Video organisation",
                            criteria="Content Type",
                            rule_type="Contains",
                            value="video/",
                            destination=os.path.join(parent_dir, "Video")
                        )
                        rules.append(rule)
                    elif file_type == "text" or file_type == "application":
                        # For documents, check for common extensions
                        doc_rule = Rule(
                            name=f"Documents organisation",
                            criteria="Extension",
                            rule_type="Equals",
                            value=".pdf,.doc,.docx,.txt,.rtf,.odt",
                            destination=os.path.join(parent_dir, "Documents")
                        )
                        rules.append(doc_rule)
                        
                        # For spreadsheets
                        spreadsheet_rule = Rule(
                            name=f"Spreadsheets organisation",
                            criteria="Extension",
                            rule_type="Equals",
                            value=".xls,.xlsx,.csv,.ods",
                            destination=os.path.join(parent_dir, "Spreadsheets")
                        )
                        rules.append(spreadsheet_rule)
        
        # Rule 2: organise by date if date patterns were found
        if self.date_patterns:
            current_year = datetime.now().year
            # For recent years
            for year in range(current_year-3, current_year+1):
                if f"year_{year}" in self.date_patterns:
                    rule = Rule(
                        name=f"Files from {year}",
                        criteria="Creation Date",
                        rule_type="Equals",
                        value=f"{year}-01-01",  # This is a simplification
                        destination=os.path.join(parent_dir, f"Files_{year}")
                    )
                    rules.append(rule)
        
        # Rule 3: organise large files if any were found
        if self.size_categories.get("large", 0) + self.size_categories.get("very_large", 0) >= 5:
            rule = Rule(
                name="Large Files",
                criteria="Size",
                rule_type="Greater Than",
                value="50MB",
                destination=os.path.join(parent_dir, "Large_Files")
            )
            rules.append(rule)
            
        # Limit to the top 5 most relevant rules
        return rules[:5]