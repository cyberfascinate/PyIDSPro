from email.mime.text import MIMEText
import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk, filedialog
from torch import view_copy
from ttkthemes import ThemedTk
import threading
import sqlite3
import configparser
import atexit
import smtplib
import os
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, TableStyle, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from reportlab.lib.units import inch
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from scapy.all import sniff, IP, TCP, UDP, DNS, ICMP
import matplotlib
matplotlib.use('TkAgg')
from matplotlib.dates import DateFormatter, HourLocator
from datetime import datetime, timedelta
import itertools
import smtplib

# Configuration Setup
config = configparser.ConfigParser()
if not os.path.exists('config.ini'):
    with open('config.ini', 'w') as configfile:
        config['EMAIL'] = {
            'server': 'smtp.gmail.com',
            'port': '587',
            'sender': 'romeo.micheal.002@gmail.com',
            'password': 'stff xfws eyzp tzvs',
            'recipient': 'shivamkadam11727@gmail.com'
        }
        config.write(configfile)
    messagebox.showwarning("Config Created", "Please edit config.ini with your email credentials")
config.read('config.ini')

# Database Setup
conn = sqlite3.connect('pyids.db', check_same_thread=False)
atexit.register(conn.close)

def initialize_db():
    try:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                timestamp TEXT,
                protocol TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                description TEXT,
                severity TEXT
            )
        ''')
        try:
            conn.execute("ALTER TABLE logs ADD COLUMN severity TEXT")
        except sqlite3.OperationalError:
            pass  # Column already exists
    except Exception as e:
        messagebox.showerror("Database Error", f"Failed to initialize database: {str(e)}")
        exit()

initialize_db()

# Email Configuration
try:
    SMTP_SERVER = config.get('EMAIL', 'server')
    SMTP_PORT = config.getint('EMAIL', 'port')
    EMAIL_SENDER = config.get('EMAIL', 'sender')
    EMAIL_PASSWORD = config.get('EMAIL', 'password')
    EMAIL_RECIPIENT = config.get('EMAIL', 'recipient')
except configparser.Error as e:
    messagebox.showerror("Configuration Error", f"Invalid config file: {e}")
    exit()

# Initialize Tkinter
root = ThemedTk(theme="equilux")
root.title("PyIDS Pro - Advanced Cyber Intrusion Detection")
root.geometry("1400x800")
root.configure(bg="#23272a")

# Styling
style = ttk.Style()
style.configure("TButton", font=("Roboto", 10, "bold"), foreground="#00ff9d", background="#2c2f33",
                borderwidth=0, focusthickness=3, focuscolor="#00ff9d", relief="flat", padding=10)
style.map('TButton', background=[('active', '#4b4f54')], foreground=[('active', '#00ff9d')])
style.configure("TFrame", background="#23272a")
style.configure("TLabel", background="#23272a", foreground="#00ff9d")
style.configure("Danger.TButton", foreground="#ff6b6b")
style.configure("Warning.TButton", foreground="#ffd700")

# Header Section
header_frame = ttk.Frame(root)
header_frame.pack(fill=tk.X, pady=10)
logo_label = tk.Label(header_frame, text="🛡️ PyIDS Pro v3.0", font=("Roboto", 20, "bold"), bg="#23272a", fg="#00ff9d")
logo_label.pack(side=tk.LEFT, padx=10)
status_indicator = tk.Label(header_frame, text="Monitoring: Inactive", font=("Roboto", 12), bg="#23272a", fg="#4a90e2")
status_indicator.pack(side=tk.RIGHT, padx=10)

# Log Display
log_frame = ttk.Frame(root)
log_frame.pack(padx=10, pady=5, fill=tk.BOTH, expand=True)
log_display = scrolledtext.ScrolledText(log_frame, width=140, height=20, bg="#1a1a1a", fg="#00ff9d",
                                        insertbackground="#00ff9d", wrap=tk.WORD, font=("Consolas", 10))
log_display.pack(fill=tk.BOTH, expand=True)
log_display.tag_config("HTTP", foreground="#00ff9d")
log_display.tag_config("DNS", foreground="#ff00c3")
log_display.tag_config("ICMP", foreground="#ffd700")
log_display.tag_config("ALERT", foreground="#ff6b6b", font=("Consolas", 10, "bold"))
log_display.tag_config("SYSTEM", foreground="#4a90e2", font=("Consolas", 10, "bold"))

# Core Functions
def db_operation(query, params=(), read=False):
    with conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        if read:
            return cursor.fetchall()

def log_incident(protocol, src_ip, dst_ip, description, severity="INFO"):
    try:
        db_operation("INSERT INTO logs (protocol, src_ip, dst_ip, description, severity) VALUES (?, ?, ?, ?, ?)",
                     (protocol, src_ip, dst_ip, description, severity))
    except sqlite3.Error as e:
        print(f"DB Error: {e}")
    tag = protocol if protocol in ["HTTP", "DNS", "ICMP", "ALERT"] else "default"
    log_entry = f"[{protocol}] {src_ip} -> {dst_ip}: {description}\n"
    log_display.insert(tk.END, log_entry, tag)
    log_display.yview(tk.END)

def analyze_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        if TCP in packet and packet[TCP].dport == 80:
            log_incident("HTTP", src_ip, dst_ip, "HTTP packet detected")
        if UDP in packet and packet[UDP].dport == 53 and DNS in packet:
            log_incident("DNS", src_ip, dst_ip, "DNS query detected")
        if ICMP in packet:
            log_incident("ICMP", src_ip, dst_ip, "ICMP packet detected")
        if TCP in packet and packet[TCP].dport in [22, 3389]:
            log_incident("ALERT", src_ip, dst_ip, f"Suspicious port {packet[TCP].dport} access", "CRITICAL")

sniffing_event = threading.Event()

def start_sniffing():
    if not sniffing_event.is_set():
        sniffing_event.set()
        log_incident("SYSTEM", "N/A", "N/A", "Started enhanced monitoring", "INFO")
        threading.Thread(target=sniff_packets, daemon=True).start()

def stop_sniffing():
    sniffing_event.clear()
    log_incident("SYSTEM", "N/A", "N/A", "Stopped monitoring", "INFO")

def sniff_packets():
    while sniffing_event.is_set():
        sniff(prn=analyze_packet, count=1, store=False, timeout=1)

# Visualization Functions
def show_pie_chart():
    try:
        data = db_operation("SELECT protocol, COUNT(*) FROM logs GROUP BY protocol", read=True)
        if not data:
            messagebox.showinfo("Pie Chart", "No data available")
            return
        protocols, counts = zip(*data)
        fig, ax = plt.subplots(figsize=(7, 7))
        colors = ['#00ff9d', '#ff00c3', '#ffd700', '#ff6b6b', '#4a90e2']
        explode = [0.05] * len(protocols)
        wedges, texts, autotexts = ax.pie(
            counts,
            labels=protocols,
            autopct='%1.1f%%',
            startangle=90,
            colors=colors,
            explode=explode,
            shadow=True,
            textprops={'color': '#00ff9d', 'fontsize': 10}
        )
        for wedge in wedges:
            wedge.set_edgecolor('#00ff9d')
            wedge.set_linewidth(0.5)
        ax.set_title("Protocol Distribution Analysis", color='#00ff9d', fontsize=14, pad=20)
        fig.set_facecolor('#23272a')
        ax.set_facecolor('#23272a')
        pie_window = tk.Toplevel(root)
        pie_window.title("Protocol Distribution Analysis")
        pie_window.configure(bg="#23272a")
        pie_window.geometry("700x700")
        canvas = FigureCanvasTkAgg(fig, master=pie_window)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to generate pie chart: {str(e)}")

def generate_advanced_report():
    try:
        # Fetch logs from the database
        logs = db_operation("SELECT timestamp, protocol, src_ip, dst_ip, description, severity FROM logs", read=True)
        
        if not logs:
            messagebox.showinfo("Report Generation", "No logs available to generate a report.")
            return
        
        # Create a PDF file
        pdf_filename = f"PyIDS_Report_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.pdf"
        doc = SimpleDocTemplate(pdf_filename, pagesize=letter)
        styles = getSampleStyleSheet()
        elements = []
        
        # Add Title
        title = Paragraph("PyIDS Pro - Intrusion Detection Report", styles['Title'])
        elements.append(title)
        elements.append(Spacer(1, 0.25 * inch))
        
        # Add Table of Logs
        table_data = [["Timestamp", "Protocol", "Source IP", "Destination IP", "Description", "Severity"]]
        table_data.extend(logs)
        
        table = Table(table_data, repeatRows=1)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.green),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        elements.append(table)
        
        # Build the PDF
        doc.build(elements)
        messagebox.showinfo("Report Generated", f"Advanced report saved as: {pdf_filename}")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to generate report: {str(e)}")
        
def send_email():
    try:
        # Check if there's a report to send
        pdf_files = [f for f in os.listdir() if f.startswith("PyIDS_Report") and f.endswith(".pdf")]
        if not pdf_files:
            messagebox.showerror("Email Error", "No report available to send.")
            return
        
        # Use the latest report
        pdf_filename = max(pdf_files, key=os.path.getctime)
        
        # Create email
        msg = MIMEMultipart()
        msg['From'] = EMAIL_SENDER
        msg['To'] = EMAIL_RECIPIENT
        msg['Subject'] = "PyIDS Pro - Intrusion Detection Report"
        body = "Please find attached the latest intrusion detection report."
        msg.attach(MIMEText(body, 'plain'))
        
        # Attach PDF
        with open(pdf_filename, "rb") as attachment:
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(attachment.read())
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', f'attachment; filename={pdf_filename}')
            msg.attach(part)
        
        # Send email
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.send_message(msg)
        
        messagebox.showinfo("Email Sent", f"Report sent to {EMAIL_RECIPIENT}")
    except Exception as e:
        messagebox.showerror("Email Error", f"Failed to send email: {str(e)}")
        
def clear_logs():
    try:
        db_operation("DELETE FROM logs")
        log_display.delete(1.0, tk.END)
        messagebox.showinfo("Logs Cleared", "All logs have been cleared.")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to clear logs: {str(e)}")   
    
def show_line_graph():
    try:
        # Fetch timestamps and counts
        query = """
            SELECT strftime('%Y-%m-%d %H:00', timestamp) AS hour, COUNT(*) AS count
            FROM logs
            GROUP BY hour
            ORDER BY hour
        """
        data = db_operation(query, read=True)
        if not data:
            messagebox.showinfo("Line Graph", "No data available")
            return
        
        hours, counts = zip(*data)
        hours = [datetime.strptime(h, '%Y-%m-%d %H:00') for h in hours]
        
        # Plot the graph
        fig, ax = plt.subplots(figsize=(10, 6))
        ax.plot(hours, counts, marker='o', color='#00ff9d', linestyle='-', linewidth=2)
        ax.set_title("Incident Timeline Analysis", color='#00ff9d', fontsize=14, pad=20)
        ax.set_ylabel("Number of Incidents", color='#00ff9d', fontsize=12)
        ax.set_xlabel("Time", color='#00ff9d', fontsize=12)
        ax.tick_params(axis='x', colors='#00ff9d')
        ax.tick_params(axis='y', colors='#00ff9d')
        ax.xaxis.set_major_formatter(DateFormatter('%Y-%m-%d %H:%M'))
        ax.xaxis.set_major_locator(HourLocator(interval=1))
        fig.autofmt_xdate()
        fig.set_facecolor('#23272a')
        ax.set_facecolor('#23272a')
        
        # Display in a new window
        line_window = tk.Toplevel(root)
        line_window.title("Incident Timeline Analysis")
        line_window.configure(bg="#23272a")
        line_window.geometry("1000x600")
        canvas = FigureCanvasTkAgg(fig, master=line_window)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to generate line graph: {str(e)}")
        
# GUI Layout Enhancements
button_frame = ttk.Frame(root)
button_frame.pack(pady=10, fill=tk.X)

control_frame = ttk.Frame(button_frame)
control_frame.pack(side=tk.LEFT, padx=20)

def create_button(parent, text, command, emoji=None, style="TButton"):
    return ttk.Button(parent, text=f"{emoji} {text}" if emoji else text, command=command, style=style)

start_btn = create_button(control_frame, "Start Monitoring", start_sniffing, "▶️")
start_btn.pack(pady=5, padx=5, fill=tk.X)
stop_btn = create_button(control_frame, "Stop Monitoring", stop_sniffing, "⏹️")
stop_btn.pack(pady=5, padx=5, fill=tk.X)

filter_frame = ttk.Frame(button_frame)
filter_frame.pack(side=tk.LEFT, padx=20)
ttk.Label(filter_frame, text="Filter by Protocol:").pack(side=tk.LEFT, padx=5)
protocol_var = tk.StringVar()
protocol_filter = ttk.Combobox(filter_frame, textvariable=protocol_var, values=["All", "HTTP", "DNS", "ICMP", "ALERT"])
protocol_filter.current(0)
protocol_filter.pack(side=tk.LEFT, padx=5)
filter_btn = create_button(filter_frame, "Apply Filter", lambda: view_copy(None if protocol_var.get() == "All" else protocol_var.get()), style="Warning.TButton")
filter_btn.pack(side=tk.LEFT, padx=5)

report_frame = ttk.Frame(button_frame)
report_frame.pack(side=tk.RIGHT, padx=20)
generate_btn = create_button(report_frame, "Generate Advanced Report", generate_advanced_report, "📄")
generate_btn.pack(pady=5, padx=5, fill=tk.X)
email_btn = create_button(report_frame, "Send Report", send_email, "📧")
email_btn.pack(pady=5, padx=5, fill=tk.X)
clear_btn = create_button(report_frame, "Clear Logs", clear_logs, "🗑️", style="Danger.TButton")
clear_btn.pack(pady=5, padx=5, fill=tk.X)

viz_frame = ttk.Frame(root)
viz_frame.pack(pady=10, fill=tk.X, padx=20)
pie_btn = create_button(viz_frame, "Protocol Analysis", show_pie_chart, "📊")
pie_btn.pack(side=tk.LEFT, expand=True, padx=5)
# line_btn = create_button(viz_frame, "Timeline Analysis", show_line_graph, "📈")
# line_btn.pack(side=tk.LEFT, expand=True, padx=5)

status_var = tk.StringVar()
status_bar = tk.Label(root, textvariable=status_var, bg="#1a1a1a", fg="#00ff9d", font=("Consolas", 10), anchor=tk.W)
status_bar.pack(side=tk.BOTTOM, fill=tk.X)

def update_status():
    total = db_operation("SELECT COUNT(*) FROM logs", read=True)[0][0]
    alerts = db_operation("SELECT COUNT(*) FROM logs WHERE severity='CRITICAL'", read=True)[0][0]
    monitoring = "Active" if sniffing_event.is_set() else "Inactive"
    status_var.set(f"Events: {total} | Alerts: {alerts} | Monitoring: {monitoring}")
    root.after(1000, update_status)

update_status()
root.mainloop()