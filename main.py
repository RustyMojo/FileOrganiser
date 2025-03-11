import os
import sys
import tkinter as tk
import logging
from file_organizer_gui import FileOrganizerGUI

def setup_logging():
    """Set up logging configuration"""
    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
    os.makedirs(log_dir, exist_ok=True)
    
    log_format = '%(asctime)s - %(levelname)s - %(message)s'
    logging.basicConfig(
        level=logging.INFO,
        format=log_format,
        handlers=[
            logging.FileHandler(os.path.join(log_dir, "file_organizer.log")),
            logging.StreamHandler()
        ]
    )

def main():
    """Main application entry point"""
    # Setup logging
    setup_logging()
    
    # Create main window
    root = tk.Tk()
    root.title("Smart File Organizer")
    
    # Set window icon if available
    try:
        if os.name == 'nt':  # Windows
            root.iconbitmap('icon.ico')
        else:  # Linux/Mac
            img = tk.PhotoImage(file='icon.png')
            root.tk.call('wm', 'iconphoto', root._w, img)
    except Exception:
        # Icon not found, continue without it
        pass
    
    # Create application instance
    app = FileOrganizerGUI(root)
    
    # Start the main loop
    root.mainloop()

if __name__ == "__main__":
    main()