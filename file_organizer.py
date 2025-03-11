import os
import logging
import concurrent.futures
from pathlib import Path
from rule import Rule

class FileOrganizer:
    """Manages file organization rules and applies them to directories"""
    
    def __init__(self):
        self.rules = []
        self.setup_logging()
        self.base_rules()

    def setup_logging(self):
        """Set up logging configuration"""
        log_format = '%(asctime)s - %(levelname)s - %(message)s'
        logging.basicConfig(
            level=logging.INFO,
            format=log_format,
            handlers=[
                logging.FileHandler("file_organizer.log"),
                logging.StreamHandler()
            ]
        )
  
    def add_rule(self, rule):
        """Add a new rule to the organizer"""
        self.rules.append(rule)
        logging.info(f"Added rule: {rule}")
        
    def remove_rule(self, rule_name):
        """Remove a rule by name"""
        for i, rule in enumerate(self.rules):
            if rule.name == rule_name:
                removed = self.rules.pop(i)
                logging.info(f"Removed rule: {removed}")
                return True
        return False
        
    def get_rules(self):
        """Get all rules"""
        return self.rules
        
    def clear_rules(self):
        """Remove all rules"""
        self.rules = []
        logging.info("Cleared all rules")
        
    def scan_directory(self, directory_path):
        """Scan a directory and return files that match any rule"""
        matches = []
        
        if not os.path.exists(directory_path) or not os.path.isdir(directory_path):
            logging.error(f"Invalid directory: {directory_path}")
            return matches
            
        for root, _, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                
                for rule in self.rules:
                    if rule.matches_file(file_path):
                        matches.append((file_path, rule))
                        break  # Only match the first applicable rule
                        
        return matches
    
    def organize_directory(self, directory_path, preview=False):
        """Organize files in a directory according to rules
        
        Args:
            directory_path (str): Path to directory to organize
            preview (bool): If True, return what would happen without moving files
            
        Returns:
            list: List of tuples containing (file_path, destination, rule_name)
        """
        results = []
        
        if not os.path.exists(directory_path) or not os.path.isdir(directory_path):
            logging.error(f"Invalid directory: {directory_path}")
            return results
            
        matches = self.scan_directory(directory_path)
        
        if preview:
            # Just return what would happen
            for file_path, rule in matches:
                results.append((file_path, rule.destination, rule.name))
        else:
            # Actually move the files
            for file_path, rule in matches:
                if rule.apply_to_file(file_path):
                    results.append((file_path, rule.destination, rule.name))
                    logging.info(f"Moved {file_path} to {rule.destination} using rule '{rule.name}'")
                else:
                    logging.warning(f"Failed to move {file_path} using rule '{rule.name}'")
                    
        return results
    
    def organize_directory_parallel(self, directory_path, max_workers=4):
        """Organize files in a directory using parallel processing"""
        if not os.path.exists(directory_path) or not os.path.isdir(directory_path):
            logging.error(f"Invalid directory: {directory_path}")
            return []
            
        matches = self.scan_directory(directory_path)
        results = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all file moves to the thread pool
            future_to_file = {
                executor.submit(rule.apply_to_file, file_path): (file_path, rule)
                for file_path, rule in matches
            }
            
            # Process results as they complete
            for future in concurrent.futures.as_completed(future_to_file):
                file_path, rule = future_to_file[future]
                try:
                    success = future.result()
                    if success:
                        results.append((file_path, rule.destination, rule.name))
                        logging.info(f"Moved {file_path} to {rule.destination} using rule '{rule.name}'")
                    else:
                        logging.warning(f"Failed to move {file_path} using rule '{rule.name}'")
                except Exception as e:
                    logging.error(f"Error processing {file_path}: {e}")
                    
        return results
    
    def save_rules(self, file_path):
        """Save rules to a file"""
        import json
        
        try:
            rules_data = [
                {
                    "name": rule.name,
                    "criteria": rule.criteria,
                    "rule_type": rule.rule_type,
                    "value": rule.value,
                    "destination": rule.destination
                }
                for rule in self.rules
            ]
            
            with open(file_path, 'w') as f:
                json.dump(rules_data, f, indent=2)
                
            logging.info(f"Saved {len(self.rules)} rules to {file_path}")
            return True
        except Exception as e:
            logging.error(f"Error saving rules to {file_path}: {e}")
            return False
    def base_rules(self):
        """Load rules from a file"""
        import json
        file_path = "./rules.json"
        try:
            with open(file_path, 'r') as f:
                rules_data = json.load(f)
                
            # Clear existing rules
            self.clear_rules()
            
            # Create new rules from data
            for rule_data in rules_data:
                rule = Rule(
                    name=rule_data["name"],
                    criteria=rule_data["criteria"],
                    rule_type=rule_data["rule_type"],
                    value=rule_data["value"],
                    destination=rule_data["destination"]
                )
                self.add_rule(rule)
                
            logging.info(f"Loaded {len(self.rules)} rules from {file_path}")
            return True
        except Exception as e:
            logging.error(f"Error loading rules from {file_path}: {e}")
            return False
        
    def load_rules(self, file_path):
        """Load rules from a file"""
        import json
        
        try:
            with open(file_path, 'r') as f:
                rules_data = json.load(f)
                
            # Clear existing rules
            self.clear_rules()
            
            # Create new rules from data
            for rule_data in rules_data:
                rule = Rule(
                    name=rule_data["name"],
                    criteria=rule_data["criteria"],
                    rule_type=rule_data["rule_type"],
                    value=rule_data["value"],
                    destination=rule_data["destination"]
                )
                self.add_rule(rule)
                
            logging.info(f"Loaded {len(self.rules)} rules from {file_path}")
            return True
        except Exception as e:
            logging.error(f"Error loading rules from {file_path}: {e}")
            return False