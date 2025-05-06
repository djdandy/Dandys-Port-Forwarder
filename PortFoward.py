import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import webbrowser
import tkinter.font as tkFont
import miniupnpc
import socket
import threading
import queue # For thread-safe communication with Tkinter

# --- Core UPnP Functions ---

def get_active_mappings(upnp_instance):
    """Retrieves a list of active UPnP port mappings, handling variations."""
    if not upnp_instance:
        return [], "UPnP device not initialized." # Return empty list for consistency

    mappings = []
    index = 0
    while True:
        mapping = None # Initialize mapping to None for the loop iteration
        try:
            # getgenericportmapping(index) returns a tuple or None
            mapping = upnp_instance.getgenericportmapping(index)

            if mapping is None:
                # No more mappings found at this index or higher
                break # Exit the loop cleanly

            # --- ROBUST UNPACKING (Handles 7 or 8 values) ---
            num_values = len(mapping)
            remote_host = '' # Default value if not provided

            if num_values == 8:
                # Standard 8-value unpack
                remote_host, ext_port_str, proto, \
                int_port_str, int_ip_str, enabled, \
                desc, lease = mapping
            elif num_values == 7:
                # Common 7-value variation (missing remote_host)
                ext_port_str, proto, \
                int_port_str, int_ip_str, enabled, \
                desc, lease = mapping
                # remote_host remains '' (our default)
            else:
                # Unexpected format - log it and skip this entry
                print(f"Warning: getgenericportmapping returned unexpected number of values ({num_values}) at index {index}. Data: {mapping}. Skipping.")
                index += 1
                continue # Move to the next index without adding

            # --- END ROBUST UNPACKING ---

            # Ensure description and lease are strings (some routers might return ints)
            desc_str = str(desc) if desc is not None else ""
            lease_str = str(lease) if lease is not None else "0"
            enabled_str = str(enabled) if enabled is not None else "0" # Usually '1' or '0'

            mappings.append({
                "external_port": str(ext_port_str), # Ensure string
                "protocol": str(proto),
                "internal_ip": str(int_ip_str),
                "internal_port": str(int_port_str),
                "description": desc_str,
                "lease_duration": lease_str,
                "enabled": enabled_str,
                "remote_host": str(remote_host)
            })

            index += 1 # Move to the next index

            # Safety break
            if index > 255:
                print("Warning: Reached mapping scan limit (256). Stopping scan.")
                break

        # --- ADJUSTED EXCEPTION HANDLING ---
        except ValueError as e:
             # Catch potential errors during unpacking if the tuple format is *still* unexpected
             # (e.g., if num_values check failed or types were wrong)
             return mappings, f"Data Error unpacking mapping at index {index}: {e}. Data was: {mapping}. List may be incomplete."
        except Exception as e:
            # Catch other unexpected errors (like network issues or library errors)
            # Use repr(e) for potentially more detail than str(e)
            # No longer relying on miniupnpc.UPnPError specifically
            error_type = type(e).__name__
            return mappings, f"{error_type} retrieving mapping at index {index}: {repr(e)}. List may be incomplete."
        # --- END ADJUSTED EXCEPTION HANDLING ---

    # If loop completed without error
    return mappings, f"Successfully retrieved {len(mappings)} active mapping(s)."

def discover_upnp_device():
    """Discovers the UPnP IGD (Internet Gateway Device) on the network."""
    upnp = None # Initialize to None
    try:
        upnp = miniupnpc.UPnP()
        upnp.discoverdelay = 200 # milliseconds to wait for responses
        # upnp.lanaddr = get_internal_ip() # You could specify interface IP if needed
        
        ndevices = upnp.discover()
        if ndevices == 0:
            return None, "No UPnP IGD devices found on the network."
        
        # Select the first valid IGD found. This might raise an exception.
        # This call should populate necessary URLs and service types.
        # It *attempts* to parse the description XML which contains the friendly name.
        try:
             upnp.selectigd() 
        except Exception as sel_err:
             # Handle errors during the selection process itself
             return None, f"Found potential device(s), but failed to select IGD: {sel_err}"

        # Now that selectigd() supposedly worked, check essential functions
        external_ip = upnp.externalipaddress()
        if not external_ip:
             # selectigd might have appeared to work but getting IP failed (common issue)
             return None, "Found UPnP device, but could not get external IP (check router UPnP config/permissions)."
        
        # Try to get the friendly name *safely*. Use a default if not found.
        # Some routers might not provide this specific field in their description.
        friendly_name = getattr(upnp, 'igd_friendly_name', 'Unknown Device/Router') 
        
        # If we got here, discovery, selection, and external IP check were successful enough
        return upnp, f"Found IGD: {friendly_name} (External IP: {external_ip})"
        
    # Catch specific library/network errors for better diagnostics
    except miniupnpc.NATPMPUnsupportedException:
         return None, "UPnP Error: NAT-PMP is not supported by the gateway."
    except miniupnpc.UPnPError as e:
         return None, f"UPnP Library Error during discovery/selection: {e}"
    except socket.error as e:
         # Handle potential network issues during discovery
         return None, f"Network/Socket Error during discovery: {e}"
    except Exception as e:
        # Catch-all for other unexpected errors during the process
        # Use repr(e) to potentially get more details than str(e)
        error_detail = repr(e) 
        # Check if the error is the specific one user reported, provide context
        if isinstance(e, AttributeError) and 'igd_friendly_name' in str(e):
             return None, f"UPnP Error: Failed to access device details ({error_detail}). Problem during IGD selection or parsing device description."
        return None, f"Generic UPnP Discovery/Setup Error: {error_detail}"

def get_internal_ip():
    """Gets the local IP address of the machine running the script."""
    s = None
    try:
        # Connect to an external server (doesn't send data) to find preferred outbound IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80)) 
        ip = s.getsockname()[0]
        return ip
    except Exception:
        try:
            # Fallback: get IP associated with hostname (might be 127.0.0.1)
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1" # Last resort fallback
    finally:
        if s:
            s.close()

def add_port_mapping(upnp_instance, external_port, internal_port, protocol, internal_ip, description):
    """Adds a port mapping rule using the UPnP object."""
    if not upnp_instance:
        return False, "UPnP device not initialized."
    try:
        # Check for existing mapping (optional but good practice)
        existing_mapping = upnp_instance.getspecificportmapping(external_port, protocol)
        if existing_mapping is not None:
             return False, f"Port {external_port}/{protocol} might already be mapped to {existing_mapping[0]}:{existing_mapping[1]}."

        # Add the new mapping
        # addportmapping(external-port, protocol, internal-host, internal-port, description, lease-duration)
        # Lease duration '0' usually means permanent or router default
        success = upnp_instance.addportmapping(
            external_port,
            protocol.upper(),
            internal_ip,
            internal_port,
            description,
            '0' 
        )
        if success:
            return True, f"Successfully mapped {external_port}/{protocol} -> {internal_ip}:{internal_port}"
        else:
            # Try getting a more specific error if available (not always reliable)
            error_code = getattr(upnp_instance, 'last_igd_error', 'Unknown UPnP error') 
            return False, f"Failed to add mapping for {external_port}/{protocol}. Router response: {error_code}"
            
    except Exception as e:
        return False, f"Error adding mapping: {e}"

def remove_port_mapping(upnp_instance, external_port, protocol):
    """Removes a port mapping rule using the UPnP object."""
    if not upnp_instance:
        return False, "UPnP device not initialized."
    try:
        # deleteportmapping(external-port, protocol)
        success = upnp_instance.deleteportmapping(external_port, protocol.upper())
        if success:
            return True, f"Successfully removed mapping for port {external_port}/{protocol}"
        else:
            # Try getting a more specific error
            error_code = getattr(upnp_instance, 'last_igd_error', 'Unknown UPnP error')
            # Common case: rule didn't exist
            if 'NoSuchEntryInArray' in str(error_code):
                 return False, f"Mapping for {external_port}/{protocol} likely did not exist."
            return False, f"Failed to remove mapping for {external_port}/{protocol}. Router response: {error_code}"
    except Exception as e:
        return False, f"Error removing mapping: {e}"

# --- Tkinter GUI Application ---

class UPnPApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Dandy's UPnP Port Mapper - v25.5.5b")
        # Increased height slightly to accommodate the list
        self.geometry("450x550") 
        self.resizable(True, True)

        self.upnp = None 
        self.internal_ip = get_internal_ip()
        self.status_queue = queue.Queue() 
        self.mapping_list_widget = None # Add this line

        self.create_widgets()
        self.check_queue() 
        self.initialize_upnp()

    def create_widgets(self):
        main_frame = ttk.Frame(self, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1) # Allow main frame row to expand

        # --- Input Fields (Rows 0-4) --- 
        # ... (keep existing input field code here) ...
        ttk.Label(main_frame, text="External Port:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.ext_port_var = tk.StringVar()
        self.ext_port_entry = ttk.Entry(main_frame, textvariable=self.ext_port_var, width=10)
        self.ext_port_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=2)
        
        ttk.Label(main_frame, text="Internal Port:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.int_port_var = tk.StringVar()
        self.int_port_entry = ttk.Entry(main_frame, textvariable=self.int_port_var, width=10)
        self.int_port_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=2)
        # self.ext_port_var.trace_add("write", self.sync_ports)

        ttk.Label(main_frame, text="Protocol:").grid(row=2, column=0, sticky=tk.W, pady=2)
        self.protocol_var = tk.StringVar(value='TCP') 
        self.protocol_combo = ttk.Combobox(main_frame, textvariable=self.protocol_var, values=['TCP', 'UDP'], state='readonly', width=8)
        self.protocol_combo.grid(row=2, column=1, sticky=tk.W, pady=2)

        ttk.Label(main_frame, text="Internal IP:").grid(row=3, column=0, sticky=tk.W, pady=2)
        self.int_ip_var = tk.StringVar(value=self.internal_ip)
        self.int_ip_entry = ttk.Entry(main_frame, textvariable=self.int_ip_var, width=20)
        self.int_ip_entry.grid(row=3, column=1, columnspan=2, sticky=(tk.W, tk.E), pady=2)

        ttk.Label(main_frame, text="Description:").grid(row=4, column=0, sticky=tk.W, pady=2)
        self.desc_var = tk.StringVar(value="Game Server") 
        self.desc_entry = ttk.Entry(main_frame, textvariable=self.desc_var, width=30)
        self.desc_entry.grid(row=4, column=1, columnspan=2, sticky=(tk.W, tk.E), pady=2)

        # --- Action Buttons (Row 5) ---
        button_frame = ttk.Frame(main_frame)
        # Added some padding below buttons
        button_frame.grid(row=5, column=0, columnspan=3, pady=(15, 5)) 

        self.add_button = ttk.Button(button_frame, text="Add Mapping", command=self.run_add_mapping, state=tk.DISABLED)
        self.add_button.pack(side=tk.LEFT, padx=5)
        
        self.remove_button = ttk.Button(button_frame, text="Remove Mapping", command=self.run_remove_mapping, state=tk.DISABLED)
        self.remove_button.pack(side=tk.LEFT, padx=5)

        # Add the new Refresh List button
        self.list_button = ttk.Button(button_frame, text="Refresh List", command=self.run_list_mappings)
        self.list_button.pack(side=tk.LEFT, padx=5)
        
        self.refresh_button = ttk.Button(button_frame, text="Refresh UPnP", command=self.initialize_upnp)
        self.refresh_button.pack(side=tk.LEFT, padx=5)

        # --- Status Area (Rows 6-7) ---
        ttk.Label(main_frame, text="Status:").grid(row=6, column=0, sticky=tk.W, pady=(10, 2))
        self.status_text = tk.Text(main_frame, height=5, wrap=tk.WORD, state=tk.DISABLED) # Reduced height slightly
        self.status_text.grid(row=7, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        status_scrollbar = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=self.status_text.yview)
        status_scrollbar.grid(row=7, column=3, sticky=(tk.N, tk.S))
        self.status_text['yscrollcommand'] = status_scrollbar.set
        
        # --- Active Mappings List (Rows 8-9) --- ADDED SECTION
        ttk.Label(main_frame, text="Active UPnP Mappings:").grid(row=8, column=0, columnspan=3, sticky=tk.W, pady=(15, 2))
        
        list_frame = ttk.Frame(main_frame)
        list_frame.grid(row=9, column=0, columnspan=4, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 5))
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)

        columns = ('#1', '#2', '#3', '#4') # Column identifiers
        self.mapping_list_widget = ttk.Treeview(list_frame, columns=columns, show='headings', height=6) # Height in rows
        
        # Define headings
        self.mapping_list_widget.heading('#1', text='Ext. Port')
        self.mapping_list_widget.heading('#2', text='Proto')
        self.mapping_list_widget.heading('#3', text='Internal Target')
        self.mapping_list_widget.heading('#4', text='Description')
        
        # Configure column widths (adjust as needed)
        self.mapping_list_widget.column('#1', width=80, anchor=tk.CENTER)
        self.mapping_list_widget.column('#2', width=50, anchor=tk.CENTER)
        self.mapping_list_widget.column('#3', width=150, anchor=tk.W)
        self.mapping_list_widget.column('#4', width=150, anchor=tk.W)

        self.mapping_list_widget.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        list_scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.mapping_list_widget.yview)
        list_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.mapping_list_widget['yscrollcommand'] = list_scrollbar.set

        # Configure main_frame grid row/column weights for expansion
        main_frame.columnconfigure(1, weight=1) 
        main_frame.rowconfigure(7, weight=1) # Status text expands
        main_frame.rowconfigure(9, weight=2) # Mapping list expands more

        # Add a row for the links at the bottom (row 10)
        main_frame.rowconfigure(10, weight=0) # Links row doesn't need to expand much

        # --- Footer Links (Row 10) --- ADDED SECTION
        link_frame = ttk.Frame(main_frame)
        link_frame.grid(row=10, column=0, columnspan=4, sticky=(tk.W, tk.E), pady=(10, 5), padx=5)

        # Create an underlined font for links
        link_font = tkFont.Font(family="TkDefaultFont", size=9, underline=False)

        github_label = ttk.Label(link_frame, text="djdandy", foreground="blue", cursor="hand2", font=link_font)
        github_label.pack(side=tk.LEFT, padx=5)
        github_label.bind("<Button-1>", self.open_github)

        website_label = ttk.Label(link_frame, text="djdandy.github.io", foreground="blue", cursor="hand2", font=link_font)
        website_label.pack(side=tk.RIGHT, padx=5)
        website_label.bind("<Button-1>", self.open_personal_page)

    # --- Link Click Handlers --- ADDED METHODS
    def open_github(self, event=None):
        webbrowser.open_new_tab("https://github.com/djdandy")

    def open_personal_page(self, event=None):
        webbrowser.open_new_tab("https://djdandy.github.io")

    # Considering adding a togglable sync for external and internal ports, for now, just copy/paste
    # def sync_ports(self, *args):
    #     """Callback to set internal port same as external port if internal is empty."""
    #     if not self.int_port_var.get():
    #         self.int_port_var.set(self.ext_port_var.get())
            
    def update_status(self, message, is_error=False):
        """Appends a message to the status text area (thread-safe)."""
        # This function runs in the main Tkinter thread via check_queue
        self.status_text.config(state=tk.NORMAL)
        tag = "error" if is_error else "info"
        self.status_text.tag_configure("error", foreground="red")
        self.status_text.tag_configure("info", foreground="blue")
        self.status_text.insert(tk.END, f"{message}\n", tag)
        self.status_text.see(tk.END) # Scroll to the bottom
        self.status_text.config(state=tk.DISABLED)

    def check_queue(self):
        """Checks the queue for messages from worker threads and updates GUI."""
        try:
            while True:
                # Get message, could be (str, bool) or ({dict}, bool)
                queue_item = self.status_queue.get_nowait() 
                
                # Check the structure of the item
                if isinstance(queue_item[0], dict) and queue_item[0].get('type') == 'mapping_list':
                    # It's our mapping list data
                    mappings = queue_item[0].get('data')
                    self.update_mapping_list(mappings) # Call the list update function
                else:
                    # Assume it's a standard status message (str, is_error)
                    message, is_error = queue_item
                    # Pass to the overridden update_status for handling
                    self.update_status(message, is_error) 
                    
                self.update_idletasks() # Ensure GUI updates immediately
        except queue.Empty:
            pass # No messages currently in queue
        
        # Schedule the next check
        self.after(100, self.check_queue) 

    def queue_status(self, message, is_error=False):
        """Puts a status message into the queue for thread-safe GUI update."""
        self.status_queue.put((message, is_error))

    def run_in_thread(self, target_func, *args):
        """Runs a function in a separate thread to avoid blocking the GUI."""
        thread = threading.Thread(target=target_func, args=args, daemon=True)
        thread.start()

    def initialize_upnp(self):
        """Attempts to discover UPnP device in a separate thread."""
        self.queue_status("Attempting UPnP discovery...")
        self.add_button.config(state=tk.DISABLED)
        self.remove_button.config(state=tk.DISABLED)
        self.run_in_thread(self._initialize_upnp_worker)

    def _initialize_upnp_worker(self):
        """Worker function for UPnP discovery."""
        self.upnp, message = discover_upnp_device()
        if self.upnp:
            self.queue_status(message, is_error=False)
            # Enable buttons on success (via queue -> check_queue -> main thread)
            self.status_queue.put(("ENABLE_BUTTONS", False)) 
            self.run_list_mappings()
        else:
            self.queue_status(message, is_error=True)
            self.status_queue.put(("DISABLE_BUTTONS", False)) # Keep disabled

        # Handle button state changes in the main thread via queue check
        
    def handle_button_state(self, state_command):
        """Handles enabling/disabling buttons from queue message."""
        if state_command == "ENABLE_BUTTONS":
             self.add_button.config(state=tk.NORMAL)
             self.remove_button.config(state=tk.NORMAL)
        elif state_command == "DISABLE_BUTTONS":
             self.add_button.config(state=tk.DISABLED)
             self.remove_button.config(state=tk.DISABLED)

    def validate_inputs(self, require_description=False):
        """Validates common input fields."""
        try:
            ext_port = int(self.ext_port_var.get())
            if not (1 <= ext_port <= 65535):
                raise ValueError("External Port must be between 1 and 65535.")
        except ValueError:
            messagebox.showerror("Input Error", "Invalid External Port number.")
            return None
        
        protocol = self.protocol_var.get()
        if protocol not in ['TCP', 'UDP']:
            messagebox.showerror("Input Error", "Invalid Protocol selected.")
            return None # Should not happen with combobox

        # For adding, we need more fields
        if require_description:
            try:
                int_port = int(self.int_port_var.get())
                if not (1 <= int_port <= 65535):
                    raise ValueError("Internal Port must be between 1 and 65535.")
            except ValueError:
                messagebox.showerror("Input Error", "Invalid Internal Port number.")
                return None
                
            int_ip = self.int_ip_var.get()
            if not int_ip: # Basic check, not a full validation
                 messagebox.showerror("Input Error", "Internal IP cannot be empty.")
                 return None
                 
            description = self.desc_var.get()
            if not description:
                 messagebox.showerror("Input Error", "Description cannot be empty.")
                 return None

            return ext_port, int_port, protocol, int_ip, description
        else:
            # For removal, we only need external port and protocol
            return ext_port, protocol

    def run_add_mapping(self):
        """Validates inputs and starts the add mapping process in a thread."""
        inputs = self.validate_inputs(require_description=True)
        if inputs:
            ext_port, int_port, protocol, int_ip, description = inputs
            self.queue_status(f"Attempting to add mapping: {ext_port}/{protocol} -> {int_ip}:{int_port}...")
            self.run_in_thread(self._add_mapping_worker, ext_port, int_port, protocol, int_ip, description)

    def _add_mapping_worker(self, ext_port, int_port, protocol, int_ip, description):
        """Worker function for adding a port mapping."""
        success, message = add_port_mapping(self.upnp, ext_port, int_port, protocol, int_ip, description)
        self.queue_status(message, is_error=not success)
        self.run_list_mappings()

    def run_remove_mapping(self):
        """Validates inputs and starts the remove mapping process in a thread."""
        inputs = self.validate_inputs(require_description=False)
        if inputs:
            ext_port, protocol = inputs
            self.queue_status(f"Attempting to remove mapping for {ext_port}/{protocol}...")
            self.run_in_thread(self._remove_mapping_worker, ext_port, protocol)

    def _remove_mapping_worker(self, ext_port, protocol):
        """Worker function for removing a port mapping."""
        success, message = remove_port_mapping(self.upnp, ext_port, protocol)
        self.queue_status(message, is_error=not success)
        self.run_list_mappings()

    def update_mapping_list(self, mappings_data):
        """Clears and repopulates the Treeview with mapping data."""
        # This runs in the main Tkinter thread via check_queue
        if self.mapping_list_widget:
            # Clear existing items
            for item in self.mapping_list_widget.get_children():
                self.mapping_list_widget.delete(item)
            
            # Insert new items
            if mappings_data:
                for mapping in mappings_data:
                    internal_target = f"{mapping['internal_ip']}:{mapping['internal_port']}"
                    self.mapping_list_widget.insert('', tk.END, values=(
                        mapping['external_port'],
                        mapping['protocol'],
                        internal_target,
                        mapping['description']
                    ))

    def run_list_mappings(self):
        """Starts the process to fetch and display active mappings."""
        if not self.upnp:
            self.queue_status("UPnP device not ready.", is_error=True)
            return
            
        self.queue_status("Fetching active mappings...")
        self.run_in_thread(self._list_mappings_worker)

    def _list_mappings_worker(self):
        """Worker thread function to get mappings and queue results."""
        mappings, message = get_active_mappings(self.upnp)
        
        # Queue the status message from get_active_mappings
        is_error = "Error" in message or "incomplete" in message
        self.queue_status(message, is_error=is_error)
        
        # Queue the actual mapping data for the list update
        # Use a specific identifier or structure to differentiate from status messages
        self.status_queue.put(({'type': 'mapping_list', 'data': mappings}, False)) 

# --- Main Execution ---
if __name__ == "__main__":
    app = UPnPApp()
     # Need to slightly modify how button states are handled from the queue
    _original_update_status = app.update_status
    def _custom_update_status(message, is_error=False):
        if message == "ENABLE_BUTTONS":
            app.handle_button_state("ENABLE_BUTTONS")
        elif message == "DISABLE_BUTTONS":
            app.handle_button_state("DISABLE_BUTTONS")
        else:
            _original_update_status(message, is_error) # Call original for normal messages
    app.update_status = _custom_update_status # Override the method instance

    app.mainloop()
