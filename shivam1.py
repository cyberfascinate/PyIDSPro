from tkinter import *
import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
from ttkthemes import ThemedTk  # For modern themes
import threading
import sqlite3
import json
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
from scapy.all import sniff, IP, TCP, UDP, DNS
import matplotlib
matplotlib.use('TkAgg')  # Set backend before importing pyplot
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg


# Database setup
conn = sqlite3.connect('pyids.db', check_same_thread=False)
cursor = conn.cursor()

cursor.execute('''CREATE TABLE IF NOT EXISTS logs
                  (timestamp TEXT, protocol TEXT, src_ip TEXT, dst_ip TEXT, description TEXT)''')
conn.commit()

atexit.register(conn.close)  # Ensure database closes properly on exit

sniffing_event = threading.Event()  # Control sniffing thread

# Email Configuration (Change these!)
SMTP_SERVER = "smtp.gmail.com"  # Example: "smtp.gmail.com" for Gmail
SMTP_PORT = 587
EMAIL_SENDER = "romeo.micheal.002@gmail.com"
EMAIL_PASSWORD = "stff xfws eyzp tzvs"
EMAIL_RECIPIENT = "shivamkadam11727@gmail.com"

# Initialize themed Tkinter
root = ThemedTk(theme="equilux")  # Cyber-themed dark theme
root.title("PyIDS - Cyber Intrusion Detection System")
root.geometry("1200x700")
root.configure(bg="#23272a")

# Custom styling
style = ttk.Style()
style.configure("TButton",
                foreground="#00ff9d",
                background="#2c2f33",
                borderwidth=0,
                focusthickness=3,
                focuscolor="#00ff9d",
                relief="flat",
                padding=10)

style.map('TButton',
          background=[('active', '#4b4f54')],
          foreground=[('active', '#00ff9d')])

style.configure("TFrame", background="#23272a")
style.configure("TLabel", background="#23272a", foreground="#00ff9d")

# Title bar
title_frame = ttk.Frame(root)
title_frame.pack(fill=X, pady=10)

title_icon = Label(title_frame, text="🌐", font=("Segoe UI Emoji", 24), bg="#23272a", fg="#00ff9d")
title_icon.pack(side=LEFT, padx=10)

title_label = Label(title_frame, text="PyIDS v2.1", font=("Consolas", 20, "bold"), 
                   bg="#23272a", fg="#00ff9d")
title_label.pack(side=LEFT)

# Log Display
log_frame = ttk.Frame(root)
log_frame.pack(padx=10, pady=5, fill=BOTH, expand=True)

log_display = scrolledtext.ScrolledText(log_frame, 
                                      width=120, 
                                      height=20,
                                      bg="#1a1a1a",
                                      fg="#00ff9d",
                                      insertbackground="#00ff9d",
                                      wrap=WORD,
                                      font=("Consolas", 10))
log_display.pack(fill=BOTH, expand=True)

# Tag configurations for different protocols
log_display.tag_config("HTTP", foreground="#00ff9d")
log_display.tag_config("DNS", foreground="#ff00c3")
log_display.tag_config("SYSTEM", foreground="#ff6b6b", font=("Consolas", 10, "bold"))

# Button Panel
button_frame = ttk.Frame(root)
button_frame.pack(pady=10, fill=X)

# Function to log incidents
def log_incident(protocol, src_ip, dst_ip, description):
    cursor.execute("INSERT INTO logs VALUES (datetime('now'), ?, ?, ?, ?)",
                   (protocol, src_ip, dst_ip, description))
    conn.commit()
    tag = protocol if protocol in ["HTTP", "DNS", "SYSTEM"] else "default"
    log_display.insert(tk.END, f"[{protocol}] {src_ip} -> {dst_ip}: {description}\n", tag)
    log_display.yview(tk.END)

# Function to analyze packets
def analyze_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        if TCP in packet and packet[TCP].dport == 80:
            log_incident("HTTP", src_ip, dst_ip, "HTTP packet detected")
        if UDP in packet and packet[UDP].dport == 53 and DNS in packet:
            log_incident("DNS", src_ip, dst_ip, "DNS query detected")

# Function to start packet sniffing
def start_sniffing():
    if not sniffing_event.is_set():
        sniffing_event.set()
        log_incident("SYSTEM", "N/A", "N/A", "Started monitoring network traffic")
        threading.Thread(target=sniff_packets, daemon=True).start()

# Function to stop packet sniffing
def stop_sniffing():
    sniffing_event.clear()
    log_incident("SYSTEM", "N/A", "N/A", "Stopped monitoring network traffic")

# Function to sniff packets
def sniff_packets():
    while sniffing_event.is_set():
        sniff(prn=analyze_packet, count=1, store=False)

# Function to view logs
def view_logs():
    cursor.execute("SELECT * FROM logs")
    logs = cursor.fetchall()
    log_display.delete(1.0, tk.END)
    for log in logs:
        log_display.insert(tk.END, f"{log[0]} - {log[1]} - {log[2]} -> {log[3]} - {log[4]}\n")

def show_graph():
    try:
        cursor.execute("SELECT protocol, COUNT(*) FROM logs GROUP BY protocol")
        data = cursor.fetchall()
        
        if not data:
            messagebox.showinfo("Graph", "No data to display.")
            return

        protocols, counts = zip(*data)
        
        # Create plot with improved styling
        fig, ax = plt.subplots(figsize=(8, 4))
        colors = ['#00ff9d', '#ff00c3', '#ff6b6b', '#4a90e2', '#d4d400']
        bars = ax.bar(protocols, counts, color=colors[:len(protocols)])
        
        ax.set_xlabel("Protocol", fontsize=10, color='#00ff9d')
        ax.set_ylabel("Number of Packets", fontsize=10, color='#00ff9d')
        ax.set_title("Network Traffic Distribution", fontsize=12, color='#00ff9d', pad=20)
        ax.tick_params(axis='x', rotation=45, labelcolor='#00ff9d')
        ax.tick_params(axis='y', labelcolor='#00ff9d')
        ax.set_facecolor('#23272a')
        fig.set_facecolor('#23272a')
        fig.tight_layout()

        # Add value labels on bars
        for bar in bars:
            height = bar.get_height()
            ax.annotate(f'{height}',
                        xy=(bar.get_x() + bar.get_width() / 2, height),
                        xytext=(0, 3),  # 3 points vertical offset
                        textcoords="offset points",
                        ha='center', va='bottom', color='#00ff9d')

        # Create graph window
        graph_window = tk.Toplevel(root)
        graph_window.title("Network Traffic Visualization")
        graph_window.configure(bg="#23272a")
        graph_window.geometry("800x400")

        canvas = FigureCanvasTkAgg(fig, master=graph_window)
        canvas.draw()
        canvas.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        plt.close(fig)  # Prevent memory leaks

    except Exception as e:
        messagebox.showerror("Graph Error", f"Failed to generate graph: {str(e)}")
        
# Function to generate PDF report
def generate_report():
    cursor.execute("SELECT * FROM logs")
    logs = cursor.fetchall()
    
    if not logs:
        messagebox.showinfo("Report", "No logs available to generate a report.")
        return None
    
    pdf_filename = "PyIDS_Report.pdf"
    
    # Create document with structured layout
    doc = SimpleDocTemplate(pdf_filename, pagesize=letter,
                            rightMargin=40, leftMargin=40,
                            topMargin=40, bottomMargin=40)
    
    styles = getSampleStyleSheet()
    elements = []
    
    # Add title
    title_style = styles['Title']
    title = Paragraph("PyIDS Intrusion Detection Report", title_style)
    elements.append(title)
    elements.append(Spacer(1, 0.25 * inch))

    # Add summary section
    elements.append(Paragraph(f"Total Events Logged: {len(logs)}", styles['Heading2']))
    
    # Protocol distribution
    protocol_counts = {}
    for log in logs:
        protocol = log[1]
        protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1
    
    summary_content = []
    for protocol, count in protocol_counts.items():
        summary_content.append(f"- {protocol}: {count} events")
    summary_text = "<br/>".join(summary_content)
    elements.append(Paragraph(summary_text, styles['BodyText']))
    elements.append(Spacer(1, 0.5 * inch))

    # Create table data with headers
    table_data = [
        ["Timestamp", "Protocol", "Source IP", "Destination IP", "Description"]
    ]
    
    # Populate table rows with log data
    for log in logs:
        timestamp = Paragraph(log[0], styles['BodyText'])
        protocol = Paragraph(log[1], styles['BodyText'])
        src_ip = Paragraph(log[2], styles['BodyText'])
        dst_ip = Paragraph(log[3], styles['BodyText'])
        description = Paragraph(log[4], styles['BodyText'])
        table_data.append([timestamp, protocol, src_ip, dst_ip, description])

    # Create table with styled columns
    log_table = Table(table_data, colWidths=[1.2*inch, 0.8*inch, 1.5*inch, 1.5*inch, 3*inch])
    log_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#003366')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('ALIGN', (0,0), (-1,0), 'CENTER'),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,0), 10),
        ('BOTTOMPADDING', (0,0), (-1,0), 12),
        ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#F0F0F0')),
        ('GRID', (0,0), (-1,-1), 1, colors.black),
        ('WORDWRAP', (4,1), (4,-1), True),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('ALIGN', (1,0), (1,-1), 'CENTER'),
    ]))

    # Add alternating row colors
    for i in range(1, len(table_data)):
        if i % 2 == 0:
            bg_color = colors.HexColor('#E8E8E8')
        else:
            bg_color = colors.HexColor('#FFFFFF')
        log_table.setStyle(TableStyle([('BACKGROUND', (0,i), (-1,i), bg_color)]))

    elements.append(log_table)
    
    # Build PDF document
    doc.build(elements)
    
    messagebox.showinfo("Report", f"Report generated: {pdf_filename}")
    return pdf_filename

# Function to send email with report
def send_email():
    report_path = generate_report()
    if not report_path:
        return
    
    msg = MIMEMultipart()
    msg['From'] = EMAIL_SENDER
    msg['To'] = EMAIL_RECIPIENT
    msg['Subject'] = "PyIDS Intrusion Detection Report"

    attachment = open(report_path, "rb")
    part = MIMEBase('application', 'octet-stream')
    part.set_payload(attachment.read())
    encoders.encode_base64(part)
    part.add_header('Content-Disposition', f"attachment; filename={os.path.basename(report_path)}")
    attachment.close()
    
    msg.attach(part)
    
    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(EMAIL_SENDER, EMAIL_PASSWORD)
        server.sendmail(EMAIL_SENDER, EMAIL_RECIPIENT, msg.as_string())
        server.quit()
        messagebox.showinfo("Email", "Report sent successfully!")
    except Exception as e:
        messagebox.showerror("Email Error", f"Failed to send email: {str(e)}")
        
# Clear Logs
def clear_logs():
    confirm = messagebox.askyesno("Clear Logs", "Are you sure you want to delete all logs? This action cannot be undone.")
    if confirm:
        cursor.execute("DELETE FROM logs")
        conn.commit()
        log_display.delete(1.0, tk.END)
        messagebox.showinfo("Clear Logs", "All logs have been deleted successfully.")

# Enhanced button creation with hover effects
def create_button(parent, text, command, emoji=None):
    btn = ttk.Button(parent, text=f"{emoji} {text}" if emoji else text, 
                    command=command, style="TButton")
    btn.bind("<Enter>", lambda e: btn.configure(style="Hover.TButton"))
    btn.bind("<Leave>", lambda e: btn.configure(style="TButton"))
    return btn

style.configure("Hover.TButton", background="#4b4f54", foreground="#00ff9d")

# Control buttons
control_frame = ttk.Frame(button_frame)
control_frame.pack(side=LEFT, padx=20)

start_btn = create_button(control_frame, "Start Monitoring", start_sniffing, "▶️")
start_btn.pack(pady=5, padx=5, fill=X)

stop_btn = create_button(control_frame, "Stop Monitoring", stop_sniffing, "⏹️")
stop_btn.pack(pady=5, padx=5, fill=X)

# Report buttons
report_frame = ttk.Frame(button_frame)
report_frame.pack(side=RIGHT, padx=20)

generate_btn = create_button(report_frame, "Generate Report", generate_report, "📄")
generate_btn.pack(pady=5, padx=5, fill=X)

email_btn = create_button(report_frame, "Send Report", send_email, "📧")
email_btn.pack(pady=5, padx=5, fill=X)

clear_btn = create_button(report_frame, "Clear Logs", clear_logs, "🗑️")
clear_btn.pack(pady=5, padx=5, fill=X)

# Graph button
graph_btn = create_button(root, "Show Traffic Graph", show_graph, "📊")
graph_btn.pack(pady=10, fill=X, padx=20)

# Status bar
status_var = StringVar()
status_bar = Label(root, textvariable=status_var, 
                  bg="#1a1a1a", fg="#00ff9d", 
                  font=("Consolas", 10), anchor=W)
status_bar.pack(side=BOTTOM, fill=X)

def update_status():
    cursor.execute("SELECT COUNT(*) FROM logs")
    count = cursor.fetchone()[0]
    status_var.set(f"Events Logged: {count} | Monitoring: {'Active' if sniffing_event.is_set() else 'Inactive'}")
    root.after(1000, update_status)

update_status()

# Run the GUI
root.mainloop()