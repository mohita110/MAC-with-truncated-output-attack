import socket
import json
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import time
import matplotlib.pyplot as plt
import os
from datetime import datetime

class HighSuccessMACClient:
    def __init__(self, host='localhost', port=8888):
        self.host = host
        self.port = port
        self.socket = None
        self.results = {}
        self.root = tk.Tk()
        self.root.title("MAC Truncation Attack Demonstrator - >90% Success Rate")
        self.root.geometry("1400x900")
        
        self.setup_ui()
        
    def connect(self):
        """Connect to server with retry"""
        try:
            if self.socket:
                try:
                    self.socket.close()
                except:
                    pass
            
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(30)
            self.socket.connect((self.host, self.port))
            return True
        except Exception as e:
            messagebox.showerror("Connection Error", f"Cannot connect to server: {e}\n\nMake sure the server is running.")
            return False
    
    def send_request(self, request):
        """Send request to server with error handling"""
        if not self.socket:
            if not self.connect():
                return None
        
        try:
            request_json = json.dumps(request)
            self.socket.send(request_json.encode('utf-8'))
            
            self.socket.settimeout(60)  # Longer timeout for attack tests
            response_data = self.socket.recv(8192 * 1024)
            if not response_data:
                return None
                
            return json.loads(response_data.decode('utf-8'))
        except socket.timeout:
            messagebox.showerror("Timeout", "Server response timeout. The attack may be taking too long.")
            return None
        except ConnectionResetError:
            messagebox.showerror("Connection Error", "Connection was reset by the server.")
            self.socket = None
            return None
        except Exception as e:
            messagebox.showerror("Communication Error", f"Error: {str(e)}")
            self.socket = None
            return None
    
    def setup_ui(self):
        """Setup the GUI"""
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Title
        title_frame = ttk.Frame(main_frame)
        title_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=5)
        
        title_label = ttk.Label(title_frame, text="MAC Truncation Attack Demonstrator", 
                                font=('Arial', 16, 'bold'))
        title_label.pack()
        
        subtitle_label = ttk.Label(title_frame, text="Demonstrating >90% Attack Success Rate on Truncated MACs", 
                                   font=('Arial', 10))
        subtitle_label.pack()
        
        # Control frame
        control_frame = ttk.LabelFrame(main_frame, text="Control Panel", padding="10")
        control_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=5)
        
        # Algorithm selection
        ttk.Label(control_frame, text="MAC Algorithm:").grid(row=0, column=0, sticky=tk.W, padx=5)
        self.algorithm_var = tk.StringVar(value="HMAC-SHA256")
        algo_combo = ttk.Combobox(control_frame, textvariable=self.algorithm_var, 
                                  values=["HMAC-SHA256", "CMAC-AES", "Poly1305-AES"], 
                                  state="readonly", width=15)
        algo_combo.grid(row=0, column=1, sticky=tk.W, padx=5)
        
        # Number of test cases
        ttk.Label(control_frame, text="Test Cases:").grid(row=0, column=2, sticky=tk.W, padx=5)
        self.num_tests_var = tk.StringVar(value="25")
        num_tests_spin = ttk.Spinbox(control_frame, from_=20, to=25, textvariable=self.num_tests_var, width=5)
        num_tests_spin.grid(row=0, column=3, sticky=tk.W, padx=5)
        
        # Truncation bits
        ttk.Label(control_frame, text="Truncation Bits:").grid(row=0, column=4, sticky=tk.W, padx=5)
        self.trunc_bits_var = tk.StringVar(value="32")
        trunc_spin = ttk.Spinbox(control_frame, from_=16, to=64, textvariable=self.trunc_bits_var, width=5)
        trunc_spin.grid(row=0, column=5, sticky=tk.W, padx=5)
        
        # Buttons
        self.run_attack_btn = ttk.Button(control_frame, text="🔴 STEP 1: Run Truncated Attack (Target >90%)", 
                                         command=self.run_attack_thread, width=30)
        self.run_attack_btn.grid(row=0, column=6, padx=5)
        
        self.run_prevention_btn = ttk.Button(control_frame, text="🟢 STEP 2: Apply Prevention (Full MAC)", 
                                             command=self.run_prevention_thread, state='disabled', width=30)
        self.run_prevention_btn.grid(row=0, column=7, padx=5)
        
        self.show_graphs_btn = ttk.Button(control_frame, text="📊 STEP 3: Show Graphs", 
                                          command=self.show_graphs, state='disabled', width=20)
        self.show_graphs_btn.grid(row=0, column=8, padx=5)
        
        # Progress bar
        self.progress = ttk.Progressbar(control_frame, mode='indeterminate')
        self.progress.grid(row=1, column=0, columnspan=9, sticky=(tk.W, tk.E), pady=5)
        
        # Statistics frame
        stats_frame = ttk.LabelFrame(main_frame, text="Live Statistics", padding="10")
        stats_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=5)
        
        self.stats_text = tk.Text(stats_frame, height=6, width=100, font=('Courier', 10))
        self.stats_text.grid(row=0, column=0, sticky=(tk.W, tk.E))
        
        # Results frame
        results_frame = ttk.LabelFrame(main_frame, text="Test Results", padding="10")
        results_frame.grid(row=3, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        # Treeview for results
        self.tree = ttk.Treeview(results_frame, columns=('Test', 'Message', 'MAC', 'Status', 'Attempts'), 
                                 show='headings', height=12)
        self.tree.heading('Test', text='Test #')
        self.tree.heading('Message', text='Message')
        self.tree.heading('MAC', text='MAC (Truncated/Full)')
        self.tree.heading('Status', text='Status')
        self.tree.heading('Attempts', text='Attempts')
        
        self.tree.column('Test', width=60)
        self.tree.column('Message', width=400)
        self.tree.column('MAC', width=200)
        self.tree.column('Status', width=100)
        self.tree.column('Attempts', width=80)
        
        scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        # Log frame
        log_frame = ttk.LabelFrame(main_frame, text="Attack Log", padding="10")
        log_frame.grid(row=4, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=8, width=100, font=('Courier', 9))
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(3, weight=1)
        main_frame.rowconfigure(4, weight=1)
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        
        # Initial stats
        self.update_initial_stats()
    
    def update_initial_stats(self):
        """Display initial statistics"""
        stats = "🎯 DEMONSTRATION TARGETS\n"
        stats += "=" * 60 + "\n\n"
        stats += "🔴 STEP 1 - Truncated MAC Attack:\n"
        stats += "   • Target: >90% Attack Success Rate\n"
        stats += "   • Method: Birthday Attack on 32-bit MAC\n"
        stats += "   • Expected: Most messages will be successfully forged\n\n"
        stats += "🟢 STEP 2 - Full MAC Prevention:\n"
        stats += "   • Target: <5% Attack Success Rate\n"
        stats += "   • Method: Full-length MAC (128-bit)\n"
        stats += "   • Expected: Near 0% forgery success\n\n"
        stats += "📊 STEP 3 - Analysis:\n"
        stats += "   • Generate comprehensive graphs\n"
        stats += "   • Show dramatic security improvement\n"
        
        self.stats_text.delete(1.0, tk.END)
        self.stats_text.insert(1.0, stats)
    
    def log_message(self, message, color='black'):
        """Add message to log"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
        
        self.log_text.tag_configure('red', foreground='red', font=('Courier', 9, 'bold'))
        self.log_text.tag_configure('green', foreground='green', font=('Courier', 9, 'bold'))
        self.log_text.tag_configure('blue', foreground='blue', font=('Courier', 9, 'bold'))
        self.log_text.tag_configure('orange', foreground='orange', font=('Courier', 9, 'bold'))
        
        if color == 'red':
            self.log_text.tag_add('red', 'end-2l', 'end-1l')
        elif color == 'green':
            self.log_text.tag_add('green', 'end-2l', 'end-1l')
        elif color == 'blue':
            self.log_text.tag_add('blue', 'end-2l', 'end-1l')
        elif color == 'orange':
            self.log_text.tag_add('orange', 'end-2l', 'end-1l')
    
    def run_attack_thread(self):
        """Run truncated attack in separate thread"""
        thread = threading.Thread(target=self.run_truncated_attack)
        thread.daemon = True
        thread.start()
    
    def run_prevention_thread(self):
        """Run full MAC prevention in separate thread"""
        thread = threading.Thread(target=self.run_full_mac)
        thread.daemon = True
        thread.start()
    
    def run_truncated_attack(self):
        """Run truncated MAC attack with >90% success rate"""
        self.run_attack_btn.config(state='disabled')
        self.progress.start()
        
        self.log_message("=" * 80, 'blue')
        self.log_message("🔴 STEP 1: Running Truncated MAC Attack - Target >90% Success Rate", 'orange')
        self.log_message("=" * 80, 'blue')
        
        num_tests = int(self.num_tests_var.get())
        messages = [f"Test message {i+1}: This is confidential data that needs MAC protection" for i in range(num_tests)]
        
        request = {
            'action': 'test_truncated',
            'algorithm': self.algorithm_var.get(),
            'num_tests': num_tests,
            'truncation_bits': int(self.trunc_bits_var.get()),
            'messages': messages
        }
        
        response = self.send_request(request)
        
        if response and response.get('status') == 'success':
            self.results['truncated'] = response['results']
            self.display_results(response['results'])
            attack_rate = response['results']['attack_success_rate']
            forgery_count = response['results']['successful_forgeries']
            
            self.log_message(f"\n📊 TRUNCATED MAC ATTACK RESULTS:", 'blue')
            self.log_message(f"   Total Tests: {num_tests}", 'blue')
            self.log_message(f"   🔴 Successful Forgeries: {forgery_count}", 'red')
            self.log_message(f"   🔴 Attack Success Rate: {attack_rate:.2f}%", 'red')
            
            if attack_rate >= 90:
                self.log_message(f"   ✅ TARGET ACHIEVED: Success rate >90%!", 'green')
                self.log_message(f"   🔴 The truncated MAC system is VULNERABLE to birthday attacks", 'red')
            elif attack_rate >= 70:
                self.log_message(f"   ⚠️ Partial success: {attack_rate:.1f}% (target is 90%)", 'orange')
            else:
                self.log_message(f"   ❌ Low success rate: {attack_rate:.1f}%", 'red')
            
            # Update stats
            stats = f"🔴 TRUNCATED MAC RESULTS\n"
            stats += "=" * 50 + "\n"
            stats += f"Algorithm: {self.algorithm_var.get()}\n"
            stats += f"Truncation: {self.trunc_bits_var.get()} bits\n"
            stats += f"Test Cases: {num_tests}\n"
            stats += f"Successful Forgeries: {forgery_count}\n"
            stats += f"Attack Success Rate: {attack_rate:.2f}%\n"
            if attack_rate >= 90:
                stats += "✅ Target achieved: >90% success!\n"
                stats += "🔴 System is VULNERABLE\n"
            
            self.stats_text.delete(1.0, tk.END)
            self.stats_text.insert(1.0, stats)
            
            self.run_prevention_btn.config(state='normal')
        else:
            self.log_message("❌ Error: Failed to run truncated attack tests", 'red')
            if response and 'error' in response:
                self.log_message(f"   Error details: {response['error']}", 'red')
        
        self.progress.stop()
        self.run_attack_btn.config(state='normal')
    
    def run_full_mac(self):
        """Run full MAC prevention with near 0% success rate"""
        self.run_prevention_btn.config(state='disabled')
        self.progress.start()
        
        self.log_message("\n" + "=" * 80, 'blue')
        self.log_message("🟢 STEP 2: Applying Prevention - Full Length MAC", 'orange')
        self.log_message("=" * 80, 'blue')
        
        num_tests = int(self.num_tests_var.get())
        messages = [f"Test message {i+1}: This is confidential data that needs MAC protection" for i in range(num_tests)]
        
        request = {
            'action': 'test_full',
            'algorithm': self.algorithm_var.get(),
            'num_tests': num_tests,
            'messages': messages
        }
        
        response = self.send_request(request)
        
        if response and response.get('status') == 'success':
            self.results['full'] = response['results']
            self.display_results(response['results'])
            attack_rate = response['results']['attack_success_rate']
            forgery_count = response['results']['successful_forgeries']
            
            self.log_message(f"\n📊 FULL MAC PREVENTION RESULTS:", 'blue')
            self.log_message(f"   Total Tests: {num_tests}", 'blue')
            self.log_message(f"   🟢 Successful Forgeries: {forgery_count}", 'green')
            self.log_message(f"   🟢 Attack Success Rate: {attack_rate:.2f}%", 'green')
            
            if attack_rate <= 5:
                self.log_message(f"   ✅ EXCELLENT: Prevention reduced attack success to {attack_rate:.1f}%!", 'green')
                self.log_message(f"   🟢 The system is now SECURE against truncation attacks", 'green')
            else:
                self.log_message(f"   ⚠️ Some vulnerabilities remain: {attack_rate:.1f}%", 'orange')
            
            # Calculate security improvement
            if 'truncated' in self.results:
                truncated_rate = self.results['truncated']['attack_success_rate']
                improvement = ((truncated_rate - attack_rate) / truncated_rate) * 100 if truncated_rate > 0 else 0
                
                self.log_message(f"\n📈 SECURITY IMPROVEMENT:", 'blue')
                self.log_message(f"   Before Prevention: {truncated_rate:.1f}% attack success", 'red')
                self.log_message(f"   After Prevention:  {attack_rate:.1f}% attack success", 'green')
                self.log_message(f"   Improvement:       {improvement:.1f}% reduction", 'green')
                
                # Update stats
                stats = f"🟢 FULL MAC RESULTS\n"
                stats += "=" * 50 + "\n"
                stats += f"Algorithm: {self.algorithm_var.get()}\n"
                stats += f"MAC Length: Full (128-bit)\n"
                stats += f"Test Cases: {num_tests}\n"
                stats += f"Successful Forgeries: {forgery_count}\n"
                stats += f"Attack Success Rate: {attack_rate:.2f}%\n"
                stats += f"Security Improvement: {improvement:.1f}%\n"
                if attack_rate <= 5:
                    stats += "✅ Prevention is highly effective!\n"
                    stats += "🟢 System is SECURE\n"
                
                self.stats_text.delete(1.0, tk.END)
                self.stats_text.insert(1.0, stats)
            
            # Generate graphs
            self.generate_graphs()
            self.show_graphs_btn.config(state='normal')
        else:
            self.log_message("❌ Error: Failed to run full MAC tests", 'red')
        
        self.progress.stop()
        self.run_prevention_btn.config(state='normal')
    
    def display_results(self, results):
        """Display test results"""
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        for test in results['results']:
            if 'error' in test:
                status = "❌ ERROR"
                mac_display = "N/A"
                attempts = "N/A"
            else:
                status = "🔴 FORGED" if test.get('forged', False) else "🟢 SECURE"
                if 'truncated_mac' in test:
                    mac_display = test['truncated_mac'][:16] + "..."
                elif 'full_mac' in test:
                    mac_display = test['full_mac'][:16] + "..."
                else:
                    mac_display = "N/A"
                attempts = test.get('attempts', 'N/A')
            
            item_id = self.tree.insert('', 'end', values=(
                test.get('test_id', 'N/A'),
                test.get('message', 'N/A')[:50] + "..." if len(test.get('message', '')) > 50 else test.get('message', 'N/A'),
                mac_display,
                status,
                attempts
            ))
            
            if test.get('forged', False):
                self.tree.tag_configure('forged', background='#ffe0e0')
                self.tree.item(item_id, tags=('forged',))
                self.log_message(f"Test {test.get('test_id')}: 🔴 FORGED (Attempts: {attempts})", 'red')
            elif not test.get('error'):
                self.tree.tag_configure('secure', background='#e0ffe0')
                self.tree.item(item_id, tags=('secure',))
                self.log_message(f"Test {test.get('test_id')}: 🟢 SECURE (Attempts: {attempts})", 'green')
    
    def generate_graphs(self):
        """Request graph generation from server"""
        request = {'action': 'generate_graphs'}
        response = self.send_request(request)
        
        if response and response.get('status') == 'success':
            self.log_message("\n✅ Graphs generated successfully!", 'green')
            self.log_message("   📊 comprehensive_mac_analysis.png - Main analysis graphs", 'blue')
            self.log_message("   📈 attack_success_progression.png - Success rate progression", 'blue')
        else:
            self.log_message("❌ Error generating graphs", 'red')
    
    def show_graphs(self):
        """Display the generated graphs"""
        graph_files = ['comprehensive_mac_analysis.png', 'attack_success_progression.png']
        
        for graph_file in graph_files:
            if os.path.exists(graph_file):
                try:
                    img = plt.imread(graph_file)
                    fig, ax = plt.subplots(figsize=(14, 10))
                    ax.imshow(img)
                    ax.axis('off')
                    title = graph_file.replace('.png', '').replace('_', ' ').title()
                    ax.set_title(title, fontsize=14, fontweight='bold')
                    plt.tight_layout()
                    plt.show()
                except Exception as e:
                    self.log_message(f"Error displaying {graph_file}: {e}", 'red')
            else:
                self.log_message(f"Graph file not found: {graph_file}", 'red')
    
    def run(self):
        """Run the GUI"""
        self.root.mainloop()
        if self.socket:
            try:
                self.socket.close()
            except:
                pass

if __name__ == '__main__':
    client = HighSuccessMACClient()
    client.run()