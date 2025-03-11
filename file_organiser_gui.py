import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import logging
from pathlib import Path
from file_analyzer import FileAnalyzer

# Import our classes
from rule import Rule
from file_organizer import FileOrganizer

class FileOrganizerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Smart File Organizer")
        self.root.geometry("900x600")
        self.root.minsize(800, 500)
        
        self.organizer = FileOrganizer()
        
        self.setup_ui()
        self.refresh_rules_list()
        
    def setup_ui(self):
        """Set up the user interface"""
        # Create a notebook with tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create tabs
        self.rules_tab = ttk.Frame(self.notebook)
        self.organize_tab = ttk.Frame(self.notebook)
        self.analysis_tab = ttk.Frame(self.notebook)
        
        self.notebook.add(self.rules_tab, text="Rules")
        self.notebook.add(self.organize_tab, text="Organize")
        self.notebook.add(self.analysis_tab, text="File Analysis")
        
        # Setup each tab
        self.setup_rules_tab()
        self.setup_organize_tab()
        self.setup_analysis_tab()
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        self.status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Menu
        self.setup_menu()
        
    def setup_menu(self):
        """Set up the application menu"""
        menubar = tk.Menu(self.root)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="New Rule Set", command=self.new_ruleset)
        file_menu.add_command(label="Open Rule Set", command=self.open_ruleset)
        file_menu.add_command(label="Save Rule Set", command=self.save_ruleset)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=self.show_about)
        help_menu.add_command(label="Help", command=self.show_help)
        
        menubar.add_cascade(label="File", menu=file_menu)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        self.root.config(menu=menubar)
        
    def setup_rules_tab(self):
        """Set up the Rules tab"""
        # Frame for rule list
        list_frame = ttk.LabelFrame(self.rules_tab, text="Rules")
        list_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Rule list with scrollbar
        self.rules_listbox = tk.Listbox(list_frame, selectmode=tk.SINGLE)
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.rules_listbox.yview)
        self.rules_listbox.configure(yscrollcommand=scrollbar.set)
        
        self.rules_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.rules_listbox.bind('<<ListboxSelect>>', self.on_rule_select)
        
        # Frame for rule details
        details_frame = ttk.LabelFrame(self.rules_tab, text="Rule Details")
        details_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Rule fields
        ttk.Label(details_frame, text="Rule Name:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.name_var = tk.StringVar()
        ttk.Entry(details_frame, textvariable=self.name_var).grid(row=0, column=1, sticky=tk.EW, padx=5, pady=5)
        
        ttk.Label(details_frame, text="Criteria:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.criteria_var = tk.StringVar()
        criteria_combo = ttk.Combobox(details_frame, textvariable=self.criteria_var)
        criteria_combo['values'] = ("Extension", "Name Pattern", "Content Type", "Creation Date", "Size")
        criteria_combo.grid(row=1, column=1, sticky=tk.EW, padx=5, pady=5)
        criteria_combo.bind('<<ComboboxSelected>>', self.on_criteria_change)
        
        ttk.Label(details_frame, text="Rule Type:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        self.rule_type_var = tk.StringVar()
        self.rule_type_combo = ttk.Combobox(details_frame, textvariable=self.rule_type_var)
        self.rule_type_combo.grid(row=2, column=1, sticky=tk.EW, padx=5, pady=5)
        
        ttk.Label(details_frame, text="Value:").grid(row=3, column=0, sticky=tk.W, padx=5, pady=5)
        self.value_var = tk.StringVar()
        ttk.Entry(details_frame, textvariable=self.value_var).grid(row=3, column=1, sticky=tk.EW, padx=5, pady=5)
        
        ttk.Label(details_frame, text="Destination:").grid(row=4, column=0, sticky=tk.W, padx=5, pady=5)
        destination_frame = ttk.Frame(details_frame)
        destination_frame.grid(row=4, column=1, sticky=tk.EW, padx=5, pady=5)
        
        self.destination_var = tk.StringVar()
        ttk.Entry(destination_frame, textvariable=self.destination_var).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(destination_frame, text="Browse", command=self.browse_destination).pack(side=tk.RIGHT)
        
        # Buttons
        button_frame = ttk.Frame(details_frame)
        button_frame.grid(row=5, column=0, columnspan=2, pady=10)
        
        ttk.Button(button_frame, text="Add/Update", command=self.add_update_rule).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Delete", command=self.delete_rule).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Clear", command=self.clear_rule_form).pack(side=tk.LEFT, padx=5)
        
        # Allow the grid to resize
        details_frame.columnconfigure(1, weight=1)
        
        # Set default values for combo boxes
        self.update_rule_type_combo()
        
    def setup_organize_tab(self):
        """Set up the Organize tab"""
        # Source directory selection
        source_frame = ttk.Frame(self.organize_tab)
        source_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(source_frame, text="Source Directory:").pack(side=tk.LEFT, padx=5)
        self.source_var = tk.StringVar()
        ttk.Entry(source_frame, textvariable=self.source_var, width=50).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        ttk.Button(source_frame, text="Browse", command=self.browse_source).pack(side=tk.LEFT, padx=5)
        
        # Action buttons
        action_frame = ttk.Frame(self.organize_tab)
        action_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(action_frame, text="Preview Organization", command=self.preview_organization).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Organize Files", command=self.organize_files).pack(side=tk.LEFT, padx=5)
        
        # Results frame
        results_frame = ttk.LabelFrame(self.organize_tab, text="Results")
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Results tree with scrollbars
        columns = ("File", "Destination", "Rule")
        self.results_tree = ttk.Treeview(results_frame, columns=columns, show='headings')
        
        # Set column headings and widths
        self.results_tree.heading("File", text="File")
        self.results_tree.heading("Destination", text="Destination")
        self.results_tree.heading("Rule", text="Rule")
        
        self.results_tree.column("File", width=300, stretch=tk.YES)
        self.results_tree.column("Destination", width=200, stretch=tk.YES)
        self.results_tree.column("Rule", width=100, stretch=tk.YES)
        
        # Add scrollbars
        vsb = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.results_tree.yview)
        hsb = ttk.Scrollbar(results_frame, orient=tk.HORIZONTAL, command=self.results_tree.xview)
        self.results_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        # Grid layout for the tree and scrollbars
        self.results_tree.grid(row=0, column=0, sticky=tk.NSEW)
        vsb.grid(row=0, column=1, sticky=tk.NS)
        hsb.grid(row=1, column=0, sticky=tk.EW)
        
        # Configure the grid
        results_frame.rowconfigure(0, weight=1)
        results_frame.columnconfigure(0, weight=1)
        
    def setup_analysis_tab(self):
        """Set up the File Analysis tab"""
        # This would connect to your AI File Analyzer
        # For now, we'll just add a placeholder frame
        
        ttk.Label(self.analysis_tab, text="AI File Analysis", font=("Arial", 16)).pack(pady=20)
        
        # Directory selection
        analysis_frame = ttk.Frame(self.analysis_tab)
        analysis_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(analysis_frame, text="Directory to Analyze:").pack(side=tk.LEFT, padx=5)
        self.analysis_dir_var = tk.StringVar()
        ttk.Entry(analysis_frame, textvariable=self.analysis_dir_var, width=50).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        ttk.Button(analysis_frame, text="Browse", command=self.browse_analysis_dir).pack(side=tk.LEFT, padx=5)
        
        # Analysis button
        ttk.Button(self.analysis_tab, text="Analyze Files", command=self.analyze_files).pack(pady=10)
        
        # Results text area
        analysis_results_frame = ttk.LabelFrame(self.analysis_tab, text="Analysis Results")
        analysis_results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.analysis_results = tk.Text(analysis_results_frame, wrap=tk.WORD)
        scrollbar = ttk.Scrollbar(analysis_results_frame, orient=tk.VERTICAL, command=self.analysis_results.yview)
        self.analysis_results.configure(yscrollcommand=scrollbar.set)
        
        self.analysis_results.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
    # Event handlers and helper methods
    def update_rule_type_combo(self):
        """Update rule type combo box based on selected criteria"""
        criteria = self.criteria_var.get()
        
        if criteria == "Extension" or criteria == "Name Pattern" or criteria == "Content Type":
            self.rule_type_combo['values'] = ("Equals", "Contains", "Matches Regex")
        elif criteria == "Creation Date":
            self.rule_type_combo['values'] = ("Equals", "Newer Than", "Older Than")
        elif criteria == "Size":
            self.rule_type_combo['values'] = ("Equals", "Greater Than", "Less Than")
        else:
            self.rule_type_combo['values'] = ()
            
        # Set default value
        if self.rule_type_combo['values']:
            self.rule_type_var.set(self.rule_type_combo['values'][0])
        else:
            self.rule_type_var.set("")
    
    def on_criteria_change(self, event):
        """Handle criteria selection change"""
        self.update_rule_type_combo()
    
    def browse_destination(self):
        """Browse for destination directory"""
        directory = filedialog.askdirectory()
        if directory:
            self.destination_var.set(directory)
    
    def browse_source(self):
        """Browse for source directory"""
        directory = filedialog.askdirectory()
        if directory:
            self.source_var.set(directory)
    
    def browse_analysis_dir(self):
        """Browse for analysis directory"""
        directory = filedialog.askdirectory()
        if directory:
            self.analysis_dir_var.set(directory)
    
    def refresh_rules_list(self):
        """Refresh the rules listbox"""
        self.rules_listbox.delete(0, tk.END)
        
        for rule in self.organizer.get_rules():
            self.rules_listbox.insert(tk.END, rule.name)
    
    def on_rule_select(self, event):
        """Handle rule selection in listbox"""
        selection = self.rules_listbox.curselection()
        if not selection:
            return
            
        index = selection[0]
        rule_name = self.rules_listbox.get(index)
        
        # Find the rule with this name
        for rule in self.organizer.get_rules():
            if rule.name == rule_name:
                self.name_var.set(rule.name)
                self.criteria_var.set(rule.criteria)
                self.update_rule_type_combo()
                self.rule_type_var.set(rule.rule_type)
                self.value_var.set(rule.value)
                self.destination_var.set(rule.destination)
                break
    
    def add_update_rule(self):
        """Add or update a rule"""
        name = self.name_var.get().strip()
        criteria = self.criteria_var.get()
        rule_type = self.rule_type_var.get()
        value = self.value_var.get().strip()
        destination = self.destination_var.get().strip()
        
        # Validate inputs
        if not name:
            messagebox.showerror("Error", "Rule name is required")
            return
            
        if not criteria:
            messagebox.showerror("Error", "Criteria is required")
            return
            
        if not rule_type:
            messagebox.showerror("Error", "Rule type is required")
            return
            
        if not value:
            messagebox.showerror("Error", "Value is required")
            return
            
        if not destination:
            messagebox.showerror("Error", "Destination is required")
            return
            
        # Check if directory exists
        if not os.path.exists(destination):
            try:
                os.makedirs(destination)
            except Exception as e:
                messagebox.showerror("Error", f"Could not create destination directory: {e}")
                return
        
        # Check if updating existing rule
        existing_rule = None
        for rule in self.organizer.get_rules():
            if rule.name == name:
                existing_rule = rule
                break
                
        if existing_rule:
            # Remove the old rule
            self.organizer.remove_rule(name)
            
        # Create and add the new rule
        new_rule = Rule(name, criteria, rule_type, value, destination)
        self.organizer.add_rule(new_rule)
        
        # Refresh the list and clear the form
        self.refresh_rules_list()
        self.clear_rule_form()
        
        self.status_var.set(f"Rule '{name}' {'updated' if existing_rule else 'added'}")
    
    def delete_rule(self):
        """Delete the selected rule"""
        selection = self.rules_listbox.curselection()
        if not selection:
            messagebox.showinfo("Info", "No rule selected")
            return
            
        index = selection[0]
        rule_name = self.rules_listbox.get(index)
        
        if messagebox.askyesno("Confirm", f"Are you sure you want to delete rule '{rule_name}'?"):
            if self.organizer.remove_rule(rule_name):
                self.refresh_rules_list()
                self.clear_rule_form()
                self.status_var.set(f"Rule '{rule_name}' deleted")
            else:
                messagebox.showerror("Error", f"Could not delete rule '{rule_name}'")
    
    def clear_rule_form(self):
        """Clear the rule form fields"""
        self.name_var.set("")
        self.criteria_var.set("")
        self.rule_type_var.set("")
        self.value_var.set("")
        self.destination_var.set("")
    
    def preview_organization(self):
        """Preview file organization without moving files"""
        source_dir = self.source_var.get().strip()
        
        if not source_dir:
            messagebox.showerror("Error", "Source directory is required")
            return
            
        if not os.path.exists(source_dir) or not os.path.isdir(source_dir):
            messagebox.showerror("Error", "Invalid source directory")
            return
            
        if not self.organizer.get_rules():
            messagebox.showinfo("Info", "No rules defined. Please add at least one rule.")
            return
            
        # Clear previous results
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
            
        # Get preview results
        results = self.organizer.organize_directory(source_dir, preview=True)
        
        if not results:
            messagebox.showinfo("Info", "No files match any rules")
            return
            
        # Populate results tree
        for file_path, destination, rule_name in results:
            rel_path = os.path.relpath(file_path, source_dir)
            self.results_tree.insert("", tk.END, values=(rel_path, destination, rule_name))
            
        self.status_var.set(f"Preview complete: {len(results)} files would be organized")
    
    def organize_files(self):
        """Organize files according to rules"""
        source_dir = self.source_var.get().strip()
        
        if not source_dir:
            messagebox.showerror("Error", "Source directory is required")
            return
            
        if not os.path.exists(source_dir) or not os.path.isdir(source_dir):
            messagebox.showerror("Error", "Invalid source directory")
            return
            
        if not self.organizer.get_rules():
            messagebox.showinfo("Info", "No rules defined. Please add at least one rule.")
            return
            
        # Confirm action
        if not messagebox.askyesno("Confirm", "This will move files according to the rules. Continue?"):
            return
            
        # Clear previous results
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
            
        # Organize files
        results = self.organizer.organize_directory(source_dir, preview=False)
        
        if not results:
            messagebox.showinfo("Info", "No files matched any rules")
            return
            
        # Populate results tree
        for file_path, destination, rule_name in results:
            rel_path = os.path.relpath(file_path, source_dir)
            self.results_tree.insert("", tk.END, values=(rel_path, destination, rule_name))
            
        self.status_var.set(f"Organization complete: {len(results)} files organized")
    
    def analyze_files(self):
        """Analyze files using AI File Analyzer"""
        analysis_dir = self.analysis_dir_var.get().strip()
        
        if not analysis_dir:
            messagebox.showerror("Error", "Analysis directory is required")
            return
            
        if not os.path.exists(analysis_dir) or not os.path.isdir(analysis_dir):
            messagebox.showerror("Error", "Invalid analysis directory")
            return
        
        # Clear previous results
        self.analysis_results.delete(1.0, tk.END)
        
        try:
            # Create an instance of FileAnalyzer
            analyzer = FileAnalyzer()
            
            # Start analysis
            self.status_var.set("Analyzing files... This may take a while")
            self.root.update()
            
            # Perform the analysis
            results = analyzer.analyze_directory(analysis_dir)
            
            # Display results
            if results:
                self.analysis_results.insert(tk.END, results)
                self.status_var.set("File analysis complete")
            else:
                self.analysis_results.insert(tk.END, "No analysis results available")
                self.status_var.set("Analysis completed with no results")
                
        except Exception as e:
            self.analysis_results.insert(tk.END, f"Error during analysis: {str(e)}")
            self.status_var.set("Analysis failed")
            logging.error(f"Analysis error: {e}")
    
    def new_ruleset(self):
        """Create a new ruleset"""
        if self.organizer.get_rules() and not messagebox.askyesno("Confirm", "Clear all current rules?"):
            return
            
        self.organizer.clear_rules()
        self.refresh_rules_list()
        self.clear_rule_form()
        self.status_var.set("New ruleset created")
    
    def save_ruleset(self):
        """Save ruleset to file"""
        if not self.organizer.get_rules():
            messagebox.showinfo("Info", "No rules to save")
            return
            
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if not file_path:
            return
            
        if self.organizer.save_rules(file_path):
            self.status_var.set(f"Ruleset saved to {file_path}")
        else:
            messagebox.showerror("Error", "Failed to save ruleset")
    
    def open_ruleset(self):
        """Open ruleset from file"""
        file_path = filedialog.askopenfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if not file_path:
            return
            
        if self.organizer.load_rules(file_path):
            self.refresh_rules_list()
            self.status_var.set(f"Ruleset loaded from {file_path}")
        else:
            messagebox.showerror("Error", "Failed to load ruleset")
    
    def show_about(self):
        """Show about dialog"""
        messagebox.showinfo(
            "About",
            "Smart File Organizer\n\n"
            "A tool to automatically organize files based on customizable rules.\n\n"
            "Version 1.0"
        )
    
    def show_help(self):
        """Show help dialog"""
        help_text = (
            "Smart File Organizer Help\n\n"
            "Rules Tab:\n"
            "- Create rules to organize files based on various criteria\n"
            "- Each rule needs a name, criteria, type, value, and destination\n\n"
            "Organize Tab:\n"
            "- Select a source directory to organize\n"
            "- Preview shows what would happen without moving files\n"
            "- Organize actually moves the files according to rules\n\n"
            "Analysis Tab:\n"
            "- Uses AI to analyze file patterns and suggest organization rules\n\n"
            "For more help, please refer to the documentation."
        )
        
        messagebox.showinfo("Help", help_text)