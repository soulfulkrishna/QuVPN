"""
Graphical user interface for the VPN client.
Provides a user-friendly interface for connecting to VPN servers.
"""
import os
import sys
import time
import threading
import logging
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import platform
from typing import Optional, Dict, Any, Callable

from client.client import VPNClient
from common.utils.config import ConfigManager
from common.utils.permissions import check_admin_privileges, elevate_privileges


class VPNClientGUI:
    """
    GUI for the VPN client
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the GUI
        
        Args:
            config_path: Path to the configuration file
        """
        # Set up logging
        self.logger = logging.getLogger("vpn_gui")
        
        # Create the main window
        self.root = tk.Tk()
        self.root.title("Post-Quantum VPN Client")
        self.root.geometry("800x600")
        self.root.minsize(640, 480)
        
        # Set up configuration
        self.config_manager = ConfigManager(config_path)
        self.vpn_client = None
        
        # Set up status variables
        self.status_var = tk.StringVar(value="Disconnected")
        self.server_var = tk.StringVar(
            value=f"{self.config_manager.get('client.server_address', '127.0.0.1')}:"
                 f"{self.config_manager.get('client.server_port', 8000)}"
        )
        self.protocol_var = tk.StringVar(
            value=self.config_manager.get('client.protocol', 'TCP').upper()
        )
        self.connected_var = tk.BooleanVar(value=False)
        
        # Build the UI
        self._build_ui()
        
        # Update status on closing
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        
        # Status update timer
        self.update_timer = None
        
        # Log startup
        self.logger.info("VPN client GUI initialized")
    
    def _build_ui(self) -> None:
        """Build the user interface"""
        # Main frame with padding
        main_frame = ttk.Frame(self.root, padding=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Status frame (top)
        status_frame = ttk.LabelFrame(main_frame, text="VPN Status", padding=10)
        status_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Status indicators
        status_grid = ttk.Frame(status_frame)
        status_grid.pack(fill=tk.X)
        
        # Connection status
        ttk.Label(status_grid, text="Status:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=3)
        status_label = ttk.Label(status_grid, textvariable=self.status_var, font=("", 0, "bold"))
        status_label.grid(row=0, column=1, sticky=tk.W, padx=5, pady=3)
        
        # Server address
        ttk.Label(status_grid, text="Server:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=3)
        ttk.Label(status_grid, textvariable=self.server_var).grid(row=1, column=1, sticky=tk.W, padx=5, pady=3)
        
        # Protocol
        ttk.Label(status_grid, text="Protocol:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=3)
        ttk.Label(status_grid, textvariable=self.protocol_var).grid(row=2, column=1, sticky=tk.W, padx=5, pady=3)
        
        # Control frame (middle)
        control_frame = ttk.LabelFrame(main_frame, text="Connection Controls", padding=10)
        control_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Connect and disconnect buttons
        button_frame = ttk.Frame(control_frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        # Connect button
        self.connect_button = ttk.Button(button_frame, text="Connect", command=self._on_connect)
        self.connect_button.pack(side=tk.LEFT, padx=5)
        
        # Disconnect button
        self.disconnect_button = ttk.Button(button_frame, text="Disconnect", command=self._on_disconnect)
        self.disconnect_button.pack(side=tk.LEFT, padx=5)
        self.disconnect_button.state(['disabled'])
        
        # Server configuration
        server_frame = ttk.Frame(control_frame)
        server_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(server_frame, text="Server Address:").pack(side=tk.LEFT, padx=5)
        self.server_entry = ttk.Entry(server_frame)
        self.server_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        self.server_entry.insert(0, self.config_manager.get("client.server_address", "127.0.0.1"))
        
        ttk.Label(server_frame, text="Port:").pack(side=tk.LEFT, padx=5)
        self.port_entry = ttk.Entry(server_frame, width=6)
        self.port_entry.pack(side=tk.LEFT, padx=5)
        self.port_entry.insert(0, str(self.config_manager.get("client.server_port", 8000)))
        
        # Protocol selector
        protocol_frame = ttk.Frame(control_frame)
        protocol_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(protocol_frame, text="Protocol:").pack(side=tk.LEFT, padx=5)
        self.protocol_combo = ttk.Combobox(protocol_frame, values=["TCP", "UDP"], state="readonly", width=5)
        self.protocol_combo.current(0 if self.config_manager.get("client.protocol", "tcp").lower() == "tcp" else 1)
        self.protocol_combo.pack(side=tk.LEFT, padx=5)
        
        # Apply server settings button
        self.apply_button = ttk.Button(protocol_frame, text="Apply Settings", command=self._on_apply_settings)
        self.apply_button.pack(side=tk.LEFT, padx=20)
        
        # Log/output frame (bottom)
        log_frame = ttk.LabelFrame(main_frame, text="Connection Log", padding=10)
        log_frame.pack(fill=tk.BOTH, expand=True)
        
        # Log text widget with scrollbar
        log_scroll = ttk.Scrollbar(log_frame)
        log_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.log_text = tk.Text(log_frame, height=10, yscrollcommand=log_scroll.set, wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        log_scroll.config(command=self.log_text.yview)
        
        # Add a custom log handler to display logs in the UI
        self.log_handler = TextHandler(self.log_text)
        self.log_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        
        root_logger = logging.getLogger()
        root_logger.addHandler(self.log_handler)
        
        # Status bar
        self.status_bar = ttk.Label(self.root, text="Ready", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Initial log message
        self.logger.info("VPN client GUI ready")
    
    def _on_connect(self) -> None:
        """Handle connect button click"""
        if not check_admin_privileges():
            self.logger.warning("Admin privileges required")
            messagebox.showwarning(
                "Admin Required",
                "This application requires administrator privileges to create network interfaces."
            )
            
            if messagebox.askyesno(
                "Restart as Admin",
                "Would you like to restart the application with administrator privileges?"
            ):
                elevate_privileges()
                # The application will restart with elevated privileges
                # This process will exit
                return
            
            return
        
        # Disable controls during connection
        self._set_controls_enabled(False)
        self.status_var.set("Connecting...")
        
        # Start VPN client in a separate thread
        threading.Thread(target=self._connect_thread, daemon=True).start()
    
    def _connect_thread(self) -> None:
        """Connection thread to avoid blocking the UI"""
        try:
            # Create VPN client if needed
            if not self.vpn_client:
                self.vpn_client = VPNClient(self.config_manager.config_path)
            
            # Start the client
            if self.vpn_client.start():
                self.connected_var.set(True)
                self.root.after(0, self._update_ui_after_connect)
                
                # Start status update timer
                if not self.update_timer:
                    self._schedule_status_update()
            else:
                self.logger.error("Failed to connect to VPN server")
                self.root.after(0, lambda: messagebox.showerror(
                    "Connection Failed",
                    "Failed to connect to VPN server. Check the logs for details."
                ))
                self.root.after(0, self._update_ui_after_disconnect)
        except Exception as e:
            self.logger.error(f"Error during connection: {e}")
            self.root.after(0, lambda: messagebox.showerror(
                "Connection Error",
                f"An error occurred during connection: {str(e)}"
            ))
            self.root.after(0, self._update_ui_after_disconnect)
    
    def _on_disconnect(self) -> None:
        """Handle disconnect button click"""
        if not self.vpn_client:
            return
            
        # Disable controls during disconnection
        self._set_controls_enabled(False)
        self.status_var.set("Disconnecting...")
        
        # Stop the client in a separate thread
        threading.Thread(target=self._disconnect_thread, daemon=True).start()
    
    def _disconnect_thread(self) -> None:
        """Disconnection thread to avoid blocking the UI"""
        try:
            if self.vpn_client:
                self.vpn_client.stop()
                
            self.connected_var.set(False)
            self.root.after(0, self._update_ui_after_disconnect)
            
            # Stop status update timer
            if self.update_timer:
                self.root.after_cancel(self.update_timer)
                self.update_timer = None
                
        except Exception as e:
            self.logger.error(f"Error during disconnection: {e}")
            self.root.after(0, lambda: messagebox.showerror(
                "Disconnection Error",
                f"An error occurred during disconnection: {str(e)}"
            ))
            self.root.after(0, self._update_ui_after_disconnect)
    
    def _on_apply_settings(self) -> None:
        """Handle apply settings button click"""
        try:
            # Get settings from UI
            server_address = self.server_entry.get().strip()
            port = self.port_entry.get().strip()
            protocol = self.protocol_combo.get().lower()
            
            # Validate settings
            if not server_address:
                messagebox.showerror("Invalid Settings", "Server address cannot be empty")
                return
                
            try:
                port = int(port)
                if port <= 0 or port > 65535:
                    raise ValueError("Port must be between 1 and 65535")
            except ValueError:
                messagebox.showerror("Invalid Settings", "Port must be a number between 1 and 65535")
                return
            
            # Update configuration
            self.config_manager.set("client.server_address", server_address)
            self.config_manager.set("client.server_port", port)
            self.config_manager.set("client.protocol", protocol)
            
            # Save configuration
            if self.config_manager.save():
                self.logger.info(f"Settings updated: {server_address}:{port} ({protocol})")
                self.server_var.set(f"{server_address}:{port}")
                self.protocol_var.set(protocol.upper())
                
                messagebox.showinfo("Settings Applied", "Server settings have been updated.")
                
                # If VPN client exists and is not connected, update its settings
                if self.vpn_client and not self.vpn_client.connected:
                    self.vpn_client.set_server(server_address, port)
            else:
                messagebox.showerror("Settings Error", "Failed to save settings")
        except Exception as e:
            self.logger.error(f"Error applying settings: {e}")
            messagebox.showerror("Settings Error", f"An error occurred while applying settings: {str(e)}")
    
    def _update_ui_after_connect(self) -> None:
        """Update UI after successful connection"""
        self.status_var.set("Connected")
        self.connect_button.state(['disabled'])
        self.disconnect_button.state(['!disabled'])
        self.server_entry.state(['disabled'])
        self.port_entry.state(['disabled'])
        self.protocol_combo.state(['disabled'])
        self.apply_button.state(['disabled'])
        self.status_bar.config(text="Connected to VPN")
    
    def _update_ui_after_disconnect(self) -> None:
        """Update UI after disconnection"""
        self.status_var.set("Disconnected")
        self.connect_button.state(['!disabled'])
        self.disconnect_button.state(['disabled'])
        self.server_entry.state(['!disabled'])
        self.port_entry.state(['!disabled'])
        self.protocol_combo.state(['readonly'])
        self.apply_button.state(['!disabled'])
        self.status_bar.config(text="Ready")
    
    def _set_controls_enabled(self, enabled: bool) -> None:
        """Enable or disable controls"""
        state = '!disabled' if enabled else 'disabled'
        
        self.connect_button.state([state])
        self.disconnect_button.state([state])
        self.server_entry.state([state])
        self.port_entry.state([state])
        self.protocol_combo.state(['readonly'] if enabled else ['disabled'])
        self.apply_button.state([state])
    
    def _schedule_status_update(self) -> None:
        """Schedule periodic status updates"""
        self._update_status()
        # Schedule next update in 2 seconds
        self.update_timer = self.root.after(2000, self._schedule_status_update)
    
    def _update_status(self) -> None:
        """Update status information from the VPN client"""
        if not self.vpn_client:
            return
            
        try:
            status = self.vpn_client.get_status()
            
            # Update connected status
            is_connected = status.get("connected", False)
            if is_connected != self.connected_var.get():
                self.connected_var.set(is_connected)
                if is_connected:
                    self._update_ui_after_connect()
                else:
                    self._update_ui_after_disconnect()
            
            # Update status message
            status_code = status.get("status", "unknown")
            status_message = status.get("message", "Unknown status")
            
            if status_code == "connected":
                self.status_var.set("Connected")
                self.status_bar.config(text=f"Connected to {status.get('server', '')}")
            elif status_code == "connecting":
                self.status_var.set("Connecting...")
                self.status_bar.config(text="Connecting to VPN server...")
            elif status_code == "disconnected":
                self.status_var.set("Disconnected")
                self.status_bar.config(text="Disconnected from VPN server")
            elif status_code == "error":
                self.status_var.set("Error")
                self.status_bar.config(text=f"Error: {status_message}")
            else:
                self.status_var.set(status_message)
            
        except Exception as e:
            self.logger.error(f"Error updating status: {e}")
    
    def _on_close(self) -> None:
        """Handle window close event"""
        if self.vpn_client and self.vpn_client.connected:
            if not messagebox.askyesno(
                "Confirm Exit",
                "VPN is still connected. Disconnect and exit?"
            ):
                return
                
            # Disconnect before exiting
            self.vpn_client.stop()
        
        # Stop status update timer
        if self.update_timer:
            self.root.after_cancel(self.update_timer)
            self.update_timer = None
        
        # Close the window
        self.root.destroy()
    
    def run(self) -> None:
        """Run the GUI main loop"""
        self.root.mainloop()


class TextHandler(logging.Handler):
    """
    Handler for redirecting logging to a tkinter Text widget
    """
    
    def __init__(self, text_widget: tk.Text):
        """
        Initialize the handler
        
        Args:
            text_widget: The text widget to write logs to
        """
        logging.Handler.__init__(self)
        self.text_widget = text_widget
        self.text_widget.tag_configure("ERROR", foreground="red")
        self.text_widget.tag_configure("WARNING", foreground="orange")
        self.text_widget.tag_configure("INFO", foreground="white")
        self.text_widget.tag_configure("DEBUG", foreground="gray")
    
    def emit(self, record: logging.LogRecord) -> None:
        """
        Write the log record to the text widget
        
        Args:
            record: The log record
        """
        msg = self.format(record)
        
        # Add the message to the text widget in the main thread
        self.text_widget.after(0, self._write_to_widget, msg, record.levelname)
    
    def _write_to_widget(self, msg: str, levelname: str) -> None:
        """
        Write a message to the text widget
        
        Args:
            msg: The formatted message
            levelname: The log level name
        """
        self.text_widget.config(state=tk.NORMAL)
        self.text_widget.insert(tk.END, msg + "\n", levelname)
        self.text_widget.see(tk.END)
        self.text_widget.config(state=tk.DISABLED)


# Main function to run the GUI
def main() -> int:
    """
    Main entry point for VPN client GUI
    
    Returns:
        Exit code
    """
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler("vpn_client_gui.log"),
            logging.StreamHandler()
        ]
    )
    
    # Create and run the GUI
    try:
        gui = VPNClientGUI()
        gui.run()
        return 0
    except Exception as e:
        logging.error(f"Error in GUI application: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
