import socket
import time
import threading
import queue
import subprocess
import re

class ESP32WiFiManager:
    def __init__(self, esp32_ip=None, port=8080):
        """Initialize ESP32 WiFi communication with improved stability"""
        self.esp32_ip = esp32_ip or self.discover_esp32()
        self.port = port
        self.socket = None
        self.connected = False
        self.message_queue = queue.Queue()
        self.listening = True
        self.reconnect_attempts = 0
        self.max_reconnect_attempts = 10
        self.last_heartbeat = time.time()
        self.connection_lock = threading.Lock()
        self.receive_buffer = ""  # Buffer for incomplete messages
        
        print(f"Initializing ESP32 WiFi Manager for {self.esp32_ip}:{self.port}")
        
        # Start connection
        self.connect()
        
        # Start listener thread
        if self.connected:
            self.listener_thread = threading.Thread(target=self._listen_for_messages)
            self.listener_thread.daemon = True
            self.listener_thread.start()
            print("ESP32 WiFi Manager connected successfully")
        else:
            print("ESP32 WiFi Manager failed to connect initially")
    
    def discover_esp32(self):
        """Automatically discover ESP32 on local network"""
        try:
            print("Attempting to discover ESP32 on network...")
            
            # Get local network range
            result = subprocess.run(['hostname', '-I'], capture_output=True, text=True)
            if result.returncode != 0:
                print("Failed to get local IP, using fallback")
                return self._get_manual_ip()
            
            local_ip = result.stdout.strip().split()[0]
            network = '.'.join(local_ip.split('.')[:-1]) + '.'
            
            print(f"Scanning network {network}0/24 for ESP32...")
            
            # Scan common IP ranges for ESP32
            ip_ranges = [
                range(100, 200),  # Common router range
                range(1, 50),     # Lower range
                range(200, 255)   # Higher range
            ]
            
            for ip_range in ip_ranges:
                for i in ip_range:
                    ip = network + str(i)
                    if ip == local_ip:  # Skip our own IP
                        continue
                    
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(0.1)
                        result = sock.connect_ex((ip, 8080))
                        sock.close()
                        
                        if result == 0:
                            print(f"Found potential ESP32 at {ip}")
                            # Verify it's actually our ESP32
                            if self._test_esp32_connection(ip):
                                print(f"Confirmed ESP32 at {ip}")
                                return ip
                    except:
                        continue
            
            print("ESP32 not found via auto-discovery")
            return self._get_manual_ip()
            
        except Exception as e:
            print(f"Network discovery failed: {e}")
            return self._get_manual_ip()
    
    def _test_esp32_connection(self, ip):
        """Test if IP is actually our ESP32"""
        try:
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_sock.settimeout(2.0)
            test_sock.connect((ip, 8080))
            
            # Look for ESP32_READY message
            test_sock.settimeout(3.0)
            response = test_sock.recv(1024).decode('utf-8').strip()
            test_sock.close()
            
            return "ESP32_READY" in response
        except:
            return False
    
    def _get_manual_ip(self):
        """Get ESP32 IP manually if auto-discovery fails"""
        print("\nAuto-discovery failed. Please enter ESP32 IP address.")
        print("Check your ESP32 Serial Monitor for the IP address.")
        
        while True:
            try:
                manual_ip = input("ESP32 IP (or press Enter for 192.168.1.100): ").strip()
                if not manual_ip:
                    return "192.168.1.100"
                
                # Validate IP format
                parts = manual_ip.split('.')
                if len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts):
                    return manual_ip
                else:
                    print("Invalid IP format. Please try again.")
            except ValueError:
                print("Invalid IP format. Please try again.")
            except KeyboardInterrupt:
                print("\nUsing default IP: 192.168.1.100")
                return "192.168.1.100"
    
    def connect(self):
        """Connect to ESP32 TCP server with improved stability"""
        with self.connection_lock:
            try:
                # Clean up existing socket
                if self.socket:
                    try:
                        self.socket.close()
                        time.sleep(1)  # Wait before creating new socket
                    except:
                        pass
                
                print(f"Connecting to ESP32 at {self.esp32_ip}:{self.port}")
                
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                
                # Set socket options for better stability
                self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                
                try:
                    # Linux/Pi specific keep-alive settings
                    self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)
                    self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
                    self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
                except OSError:
                    # Some systems don't support these options
                    pass
                
                # Longer timeout for connection stability
                self.socket.settimeout(20)
                
                # Connect to ESP32
                self.socket.connect((self.esp32_ip, self.port))
                
                # Wait for connection to stabilize
                time.sleep(0.5)
                
                self.connected = True
                self.reconnect_attempts = 0
                self.last_heartbeat = time.time()
                self.receive_buffer = ""  # Reset buffer on new connection
                
                print(f"✓ Connected to ESP32 at {self.esp32_ip}:{self.port}")
                
                # Wait for ESP32 ready message
                self.socket.settimeout(10.0)
                try:
                    ready_msg = self.socket.recv(1024).decode('utf-8').strip()
                    if "ESP32_READY" in ready_msg:
                        print("✓ ESP32 confirmed ready for commands")
                        return True
                    else:
                        print(f"⚠ Received: {ready_msg}")
                        return True  # Continue anyway
                except socket.timeout:
                    print("⚠ No ready message, but connection seems stable")
                    return True
                
            except Exception as e:
                print(f"✗ Failed to connect to ESP32: {e}")
                self.connected = False
                if self.socket:
                    try:
                        self.socket.close()
                    except:
                        pass
                self.socket = None
                return False
    
    def reconnect(self):
        """Attempt to reconnect with exponential backoff"""
        if self.reconnect_attempts >= self.max_reconnect_attempts:
            print(f"✗ Max reconnection attempts ({self.max_reconnect_attempts}) reached")
            return False
        
        self.reconnect_attempts += 1
        wait_time = min(2 ** self.reconnect_attempts, 30)  # Max 30s wait
        
        print(f"🔄 Reconnection attempt {self.reconnect_attempts}/{self.max_reconnect_attempts}")
        print(f"   Waiting {wait_time} seconds before retry...")
        
        time.sleep(wait_time)
        return self.connect()
    
    def _parse_messages_from_buffer(self, data):
        """Parse multiple messages from received data buffer"""
        # Add new data to buffer
        self.receive_buffer += data
        
        messages = []
        
        # Split by newlines and process complete messages
        while '\n' in self.receive_buffer:
            line, self.receive_buffer = self.receive_buffer.split('\n', 1)
            
            # Clean the message (remove \r and whitespace)
            clean_message = line.strip().replace('\r', '')
            
            if clean_message:  # Only process non-empty messages
                messages.append(clean_message)
        
        return messages
    
    def _listen_for_messages(self):
        """Enhanced message listener with proper message parsing"""
        consecutive_errors = 0
        last_activity = time.time()
        
        print("📡 Message listener thread started")
        
        while self.listening:
            try:
                if self.socket and self.connected:
                    self.socket.settimeout(2.0)
                    
                    try:
                        raw_data = self.socket.recv(1024).decode('utf-8')
                        
                        if raw_data:
                            consecutive_errors = 0
                            last_activity = time.time()
                            
                            # Parse multiple messages from the received data
                            messages = self._parse_messages_from_buffer(raw_data)
                            
                            for message in messages:
                                # Handle heartbeat messages
                                if message == "HEARTBEAT":
                                    self.last_heartbeat = time.time()
                                    continue
                                
                                # Queue other messages
                                self.message_queue.put(message)
                                print(f"📨 ESP32: {message}")
                            
                        elif raw_data == '':
                            print("📡 ESP32 closed connection")
                            self.connected = False
                            consecutive_errors += 1
                        
                    except socket.timeout:
                        current_time = time.time()
                        
                        # Check for missed heartbeats
                        if current_time - self.last_heartbeat > 30:
                            print("💔 No heartbeat received, connection may be dead")
                            self.connected = False
                        
                        # Send ping periodically
                        elif current_time - last_activity > 60:
                            print("🔍 Sending ping to check connection...")
                            if not self.send_command("PING"):
                                self.connected = False
                            last_activity = current_time
                        
                        continue
                        
                    except socket.error as e:
                        print(f"📡 Socket error in listener: {e}")
                        self.connected = False
                        consecutive_errors += 1
                
                # Handle reconnection
                if not self.connected:
                    if consecutive_errors < 3:
                        print("🔄 Connection lost, attempting to reconnect...")
                        if self.reconnect():
                            consecutive_errors = 0
                            last_activity = time.time()
                            continue
                        else:
                            consecutive_errors += 1
                    else:
                        print("⏸ Too many errors, waiting longer...")
                        time.sleep(10)
                        consecutive_errors = 0
                
                time.sleep(0.1)
                
            except Exception as e:
                print(f"📡 Unexpected error in listener: {e}")
                consecutive_errors += 1
                if consecutive_errors >= 5:
                    time.sleep(5)
                    consecutive_errors = 0
                else:
                    time.sleep(1)
        
        print("📡 Message listener thread stopped")
    
    def send_command(self, command):
        """Enhanced command sending with retry logic"""
        with self.connection_lock:
            max_retries = 3
            
            for attempt in range(max_retries):
                if not self.connected:
                    if not self.reconnect():
                        if attempt < max_retries - 1:
                            time.sleep(1)
                            continue
                        else:
                            return False
                
                try:
                    if self.socket and self.connected:
                        message = (command + '\n').encode('utf-8')
                        self.socket.send(message)
                        
                        if command != "PING":
                            print(f"📤 Sent to ESP32: {command}")
                        
                        return True
                        
                except Exception as e:
                    print(f"📤 Error sending command (attempt {attempt + 1}): {e}")
                    self.connected = False
                    
                    if attempt < max_retries - 1:
                        time.sleep(1)
                    else:
                        return False
            
            return False
    
    def start_token_scan(self, team, num_scans):
        """Start token scanning session"""
        if not isinstance(team, str) or team not in ['A', 'B']:
            print(f"⚠ Invalid team: {team}")
            return False
            
        if not isinstance(num_scans, int) or num_scans <= 0 or num_scans > 10:
            print(f"⚠ Invalid scan count: {num_scans}")
            return False
        
        command = f"START_SCAN:{team}:{num_scans}"
        success = self.send_command(command)
        
        if success:
            print(f"🎯 Token scan initiated: Team {team} needs {num_scans} scans")
        else:
            print(f"✗ Failed to start token scan for Team {team}")
        
        return success
    
    def get_token_counts(self):
        """Request current token counts"""
        return self.send_command("GET_TOKENS")
    
    def reset_tokens(self):
        """Reset tokens to 10 each"""
        success = self.send_command("RESET_TOKENS")
        if success:
            print("🔄 Token reset command sent")
        return success
    
    def get_system_status(self):
        """Get system status"""
        return self.send_command("STATUS")
    
    def ping(self):
        """Send ping to ESP32"""
        return self.send_command("PING")
    
    def get_message(self):
        """Get message from ESP32 (non-blocking)"""
        try:
            return self.message_queue.get_nowait()
        except queue.Empty:
            return None
    
    def get_message_timeout(self, timeout=1.0):
        """Get message with timeout"""
        try:
            return self.message_queue.get(timeout=timeout)
        except queue.Empty:
            return None
    
    def is_connected(self):
        """Check connection status"""
        return self.connected and self.socket is not None
    
    def get_connection_info(self):
        """Get connection information"""
        return {
            'connected': self.connected,
            'esp32_ip': self.esp32_ip,
            'port': self.port,
            'reconnect_attempts': self.reconnect_attempts,
            'last_heartbeat': self.last_heartbeat,
            'queue_size': self.message_queue.qsize()
        }
    
    def close(self):
        """Close connection and cleanup"""
        print("🔌 Closing ESP32 WiFi Manager...")
        
        self.listening = False
        self.connected = False
        
        # Wait for listener thread
        if hasattr(self, 'listener_thread') and self.listener_thread.is_alive():
            self.listener_thread.join(timeout=2.0)
        
        # Close socket
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
            self.socket = None
        
        # Clear message queue
        while not self.message_queue.empty():
            try:
                self.message_queue.get_nowait()
            except queue.Empty:
                break
        
        print("✓ ESP32 WiFi connection closed cleanly")
