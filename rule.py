import os
import re
import shutil
import logging
from datetime import datetime
from pathlib import Path

class Rule:
    """Represents a file organization rule"""
    def __init__(self, name, criteria, rule_type, value, destination):
        self.name = name
        self.criteria = criteria  # Extension, Name Pattern, Content Type, Creation Date, Size
        self.rule_type = rule_type  # Equals, Contains, Matches Regex, Newer Than, Older Than, etc.
        self.value = value  # The value to match against
        self.destination = destination  # Destination folder
        
    def matches_file(self, file_path):
        """Check if the rule matches the given file"""
        if not os.path.exists(file_path) or os.path.isdir(file_path):
            return False
            
        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)
        file_ext = os.path.splitext(file_name)[1].lower()
        
        # Check based on criteria
        if self.criteria == "Extension":
            return self._match_extension(file_ext)
        elif self.criteria == "Name Pattern":
            return self._match_name_pattern(file_name)
        elif self.criteria == "Content Type":
            return self._match_content_type(file_path)
        elif self.criteria == "Creation Date":
            return self._match_creation_date(file_path)
        elif self.criteria == "Size":
            return self._match_size(file_size)
        
        return False
    
    def _match_extension(self, file_ext):
        """Match file extension against rule"""
        if self.rule_type == "Equals":
            # Handle comma-separated list of extensions
            exts = [ext.strip().lower() for ext in self.value.split(',')]
            return file_ext.lower() in exts
        elif self.rule_type == "Contains":
            return self.value.lower() in file_ext.lower()
        elif self.rule_type == "Matches Regex":
            try:
                return bool(re.search(self.value, file_ext, re.IGNORECASE))
            except:
                return False
        return False
    
    def _match_name_pattern(self, file_name):
        """Match filename against rule"""
        if self.rule_type == "Equals":
            return file_name.lower() == self.value.lower()
        elif self.rule_type == "Contains":
            # Check for any value in a comma-separated list
            patterns = [pat.strip().lower() for pat in self.value.split(',')]
            return any(pat in file_name.lower() for pat in patterns)
        elif self.rule_type == "Matches Regex":
            try:
                return bool(re.search(self.value, file_name, re.IGNORECASE))
            except:
                return False
        return False
    
    def _match_content_type(self, file_path):
        """Match content type of file"""
        # In a full implementation, this would inspect the file content
        # For simplicity, we're just checking basic MIME type
        import mimetypes
        mime_type, _ = mimetypes.guess_type(file_path)
        
        if not mime_type:
            return False
            
        if self.rule_type == "Equals":
            return mime_type == self.value
        elif self.rule_type == "Contains":
            return self.value in mime_type
        elif self.rule_type == "Matches Regex":
            try:
                return bool(re.search(self.value, mime_type, re.IGNORECASE))
            except:
                return False
        return False
    
    def _match_creation_date(self, file_path):
        """Match file creation date against rule"""
        try:
            # Get file creation time (or modification time as fallback)
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
            
            # Parse the rule value as a date
            try:
                # Check if the value is a relative time description
                if self.value.lower() in ["today", "yesterday"]:
                    today = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
                    if self.value.lower() == "today":
                        comparison_date = today
                    else:  # yesterday
                        from datetime import timedelta
                        comparison_date = today - timedelta(days=1)
                else:
                    # Try different date formats
                    for fmt in ["%Y-%m-%d", "%m/%d/%Y", "%d-%m-%Y", "%d/%m/%Y"]:
                        try:
                            comparison_date = datetime.strptime(self.value, fmt)
                            break
                        except ValueError:
                            continue
                    else:
                        return False  # Could not parse date
                
                # Compare dates based on rule type
                if self.rule_type == "Equals":
                    return file_date.date() == comparison_date.date()
                elif self.rule_type == "Newer Than":
                    return file_date.date() > comparison_date.date()
                elif self.rule_type == "Older Than":
                    return file_date.date() < comparison_date.date()
                
            except Exception as e:
                logging.error(f"Error parsing date: {e}")
                return False
                
        except Exception as e:
            logging.error(f"Error getting file creation date: {e}")
            return False
            
        return False
    
    def _match_size(self, file_size):
        """Match file size against rule"""
        try:
            # Convert value to bytes based on units (KB, MB, GB)
            size_value = self.value.strip().upper()
            
            if size_value.endswith("KB"):
                comparison_size = float(size_value[:-2]) * 1024
            elif size_value.endswith("MB"):
                comparison_size = float(size_value[:-2]) * 1024 * 1024
            elif size_value.endswith("GB"):
                comparison_size = float(size_value[:-2]) * 1024 * 1024 * 1024
            else:
                # Assume bytes if no unit specified
                comparison_size = float(size_value)
            
            # Compare based on rule type
            if self.rule_type == "Equals":
                return file_size == comparison_size
            elif self.rule_type == "Greater Than":
                return file_size > comparison_size
            elif self.rule_type == "Less Than":
                return file_size < comparison_size
                
        except Exception as e:
            logging.error(f"Error comparing file size: {e}")
            return False
            
        return False
    
    def apply_to_file(self, file_path):
        """Apply the rule to a file by moving it to the destination folder"""
        if not self.matches_file(file_path):
            return False
            
        # Create destination directory if it doesn't exist
        os.makedirs(self.destination, exist_ok=True)
        
        # Get target file path
        file_name = os.path.basename(file_path)
        target_path = os.path.join(self.destination, file_name)
        
        # Handle file name conflicts
        if os.path.exists(target_path):
            base_name, extension = os.path.splitext(file_name)
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            new_name = f"{base_name}_{timestamp}{extension}"
            target_path = os.path.join(self.destination, new_name)
        
        try:
            # Move the file
            shutil.move(file_path, target_path)
            return True
        except Exception as e:
            logging.error(f"Error moving file {file_path} to {target_path}: {e}")
            return False
    
    def __repr__(self):
        """String representation of the rule"""
        return f"Rule('{self.name}', {self.criteria} {self.rule_type} '{self.value}' -> '{self.destination}')"