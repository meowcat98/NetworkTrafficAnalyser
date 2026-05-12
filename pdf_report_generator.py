# PDF Report Generator for Network Traffic Analyzer
# Requires: pip install reportlab pillow

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak, Image
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.pdfgen import canvas
from datetime import datetime
import matplotlib.pyplot as plt
from collections import Counter
import csv
import os
import io

class NetworkTrafficReportGenerator:
    """
    Generates professional PDF reports from network traffic analysis data
    """
    
    def __init__(self, csv_path="live_packets.csv", alert_log="security_alerts.log"):
        self.csv_path = csv_path
        self.alert_log = alert_log
        self.styles = getSampleStyleSheet()
        self.setup_custom_styles()
        
    def setup_custom_styles(self):
        """Create custom paragraph styles"""
        # Title style
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1a1a1a'),
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))
        
        # Section header
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#2c3e50'),
            spaceAfter=12,
            spaceBefore=12,
            fontName='Helvetica-Bold'
        ))
        
        # Alert style
        self.styles.add(ParagraphStyle(
            name='Alert',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=colors.HexColor('#c0392b'),
            fontName='Courier',
            leftIndent=20
        ))
        
        # Summary box
        self.styles.add(ParagraphStyle(
            name='Summary',
            parent=self.styles['Normal'],
            fontSize=11,
            leading=16,
            textColor=colors.HexColor('#34495e')
        ))
    
    def analyze_csv_data(self):
        """Parse CSV and extract statistics"""
        if not os.path.exists(self.csv_path):
            return None
        
        data = {
            'total_packets': 0,
            'total_bytes': 0,
            'protocols': Counter(),
            'top_sources': Counter(),
            'top_destinations': Counter(),
            'top_ports': Counter(),
            'timestamps': [],
            'start_time': None,
            'end_time': None
        }
        
        try:
            with open(self.csv_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    data['total_packets'] += 1
                    
                    # Track bytes
                    if 'len' in row and row['len']:
                        data['total_bytes'] += int(row['len'])
                    
                    # Protocol distribution
                    if 'proto' in row:
                        data['protocols'][row['proto']] += 1
                    
                    # Top IPs
                    if 'src' in row:
                        data['top_sources'][row['src']] += 1
                    if 'dst' in row:
                        data['top_destinations'][row['dst']] += 1
                    
                    # Top ports
                    if 'dport' in row and row['dport']:
                        data['top_ports'][row['dport']] += 1
                    
                    # Timestamps
                    if 'time' in row:
                        data['timestamps'].append(row['time'])
                        if not data['start_time']:
                            data['start_time'] = row['time']
                        data['end_time'] = row['time']
            
            return data
        except Exception as e:
            print(f"Error analyzing CSV: {e}")
            return None
    
    def load_alerts(self):
        """Load security alerts from log file"""
        alerts = []
        if not os.path.exists(self.alert_log):
            return alerts
        
        try:
            with open(self.alert_log, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip() and not line.startswith('==='):
                        alerts.append(line.strip())
        except Exception as e:
            print(f"Error loading alerts: {e}")
        
        return alerts
    
    def create_chart_image(self, data, chart_type='protocols'):
        """Generate matplotlib charts and return as image buffer"""
        fig, ax = plt.subplots(figsize=(6, 4))
        
        if chart_type == 'protocols' and data['protocols']:
            labels = list(data['protocols'].keys())
            sizes = list(data['protocols'].values())
            colors_pie = ['#3498db', '#e74c3c', '#2ecc71', '#f39c12']
            ax.pie(sizes, labels=labels, autopct='%1.1f%%', colors=colors_pie, startangle=90)
            ax.set_title('Protocol Distribution', fontsize=12, weight='bold')
            
        elif chart_type == 'top_sources' and data['top_sources']:
            ips = [ip for ip, _ in data['top_sources'].most_common(10)]
            counts = [count for _, count in data['top_sources'].most_common(10)]
            ax.barh(range(len(ips)), counts, color='#3498db')
            ax.set_yticks(range(len(ips)))
            ax.set_yticklabels(ips, fontsize=8)
            ax.invert_yaxis()
            ax.set_xlabel('Packet Count')
            ax.set_title('Top 10 Source IPs', fontsize=12, weight='bold')
            ax.grid(axis='x', alpha=0.3)
            
        elif chart_type == 'top_destinations' and data['top_destinations']:
            ips = [ip for ip, _ in data['top_destinations'].most_common(10)]
            counts = [count for _, count in data['top_destinations'].most_common(10)]
            ax.barh(range(len(ips)), counts, color='#e74c3c')
            ax.set_yticks(range(len(ips)))
            ax.set_yticklabels(ips, fontsize=8)
            ax.invert_yaxis()
            ax.set_xlabel('Packet Count')
            ax.set_title('Top 10 Destination IPs', fontsize=12, weight='bold')
            ax.grid(axis='x', alpha=0.3)
        
        plt.tight_layout()
        
        # Save to buffer
        buf = io.BytesIO()
        plt.savefig(buf, format='png', dpi=150, bbox_inches='tight')
        buf.seek(0)
        plt.close()
        
        return buf
    
    def format_bytes(self, bytes_val):
        """Convert bytes to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_val < 1024.0:
                return f"{bytes_val:.2f} {unit}"
            bytes_val /= 1024.0
        return f"{bytes_val:.2f} PB"
    
    def generate_report(self, output_path="network_traffic_report.pdf"):
        """Generate complete PDF report"""
        
        # Analyze data
        data = self.analyze_csv_data()
        if not data:
            print("❌ No data found. Make sure capture has been run.")
            return False
        
        alerts = self.load_alerts()
        
        # Create PDF
        doc = SimpleDocTemplate(output_path, pagesize=letter,
                              rightMargin=72, leftMargin=72,
                              topMargin=72, bottomMargin=18)
        
        story = []
        
        story.append(Spacer(1, 2*inch))
        
        title = Paragraph("Network Traffic Analysis Report", self.styles['CustomTitle'])
        story.append(title)
        story.append(Spacer(1, 0.3*inch))
        
        subtitle = Paragraph(
            f"Security Monitoring & Analysis<br/>"
            f"Generated: {datetime.now().strftime('%B %d, %Y at %H:%M:%S')}",
            ParagraphStyle('subtitle', parent=self.styles['Normal'], 
                         fontSize=12, alignment=TA_CENTER, textColor=colors.grey)
        )
        story.append(subtitle)
        story.append(Spacer(1, 1*inch))
        
        # Executive Summary Box
        summary_data = [
            ['Total Packets Captured:', f"{data['total_packets']:,}"],
            ['Total Data Transferred:', self.format_bytes(data['total_bytes'])],
            ['Capture Start:', data['start_time'] or 'N/A'],
            ['Capture End:', data['end_time'] or 'N/A'],
            ['Security Alerts:', str(len(alerts))],
        ]
        
        summary_table = Table(summary_data, colWidths=[3*inch, 2.5*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#ecf0f1')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#2c3e50')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('PADDING', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#bdc3c7'))
        ]))
        story.append(summary_table)
        
        story.append(PageBreak())
        
        story.append(Paragraph("Executive Summary", self.styles['SectionHeader']))
        story.append(Spacer(1, 0.2*inch))
        
        # Calculate some insights
        top_proto = data['protocols'].most_common(1)[0] if data['protocols'] else ('N/A', 0)
        top_src = data['top_sources'].most_common(1)[0] if data['top_sources'] else ('N/A', 0)
        
        summary_text = f"""
        This report presents a comprehensive analysis of network traffic captured during the monitoring period 
        from {data['start_time']} to {data['end_time']}. A total of {data['total_packets']:,} packets 
        were captured, representing {self.format_bytes(data['total_bytes'])} of data transfer.
        <br/><br/>
        The dominant protocol observed was <b>{top_proto[0]}</b> ({top_proto[1]:,} packets, 
        {(top_proto[1]/data['total_packets']*100):.1f}% of total traffic). 
        The most active source IP address was <b>{top_src[0]}</b> with {top_src[1]:,} packets transmitted.
        <br/><br/>
        {'<font color="red"><b>Security Concern:</b> ' + str(len(alerts)) + ' security alerts were triggered during this capture period. Immediate review recommended.</font>' if alerts else '<font color="green"><b>Security Status:</b> No security alerts were triggered during this capture period.</font>'}
        """
        
        story.append(Paragraph(summary_text, self.styles['Summary']))
        story.append(Spacer(1, 0.3*inch))
        
        story.append(PageBreak())
        story.append(Paragraph("Protocol Distribution Analysis", self.styles['SectionHeader']))
        story.append(Spacer(1, 0.2*inch))
        
        if data['protocols']:
            # Add protocol chart
            chart_buf = self.create_chart_image(data, 'protocols')
            img = Image(chart_buf, width=5*inch, height=3.5*inch)
            story.append(img)
            story.append(Spacer(1, 0.2*inch))
            
            # Protocol breakdown table
            proto_data = [['Protocol', 'Packet Count', 'Percentage']]
            for proto, count in data['protocols'].most_common():
                percentage = (count / data['total_packets']) * 100
                proto_data.append([proto, f"{count:,}", f"{percentage:.2f}%"])
            
            proto_table = Table(proto_data, colWidths=[2*inch, 2*inch, 2*inch])
            proto_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3498db')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(proto_table)
        
        story.append(PageBreak())
        story.append(Paragraph("Top Source IP Addresses", self.styles['SectionHeader']))
        story.append(Spacer(1, 0.2*inch))
        
        chart_buf = self.create_chart_image(data, 'top_sources')
        img = Image(chart_buf, width=6*inch, height=4*inch)
        story.append(img)
        story.append(Spacer(1, 0.2*inch))
        
        # Top sources table
        src_data = [['Rank', 'IP Address', 'Packet Count', '% of Total']]
        for i, (ip, count) in enumerate(data['top_sources'].most_common(10), 1):
            percentage = (count / data['total_packets']) * 100
            src_data.append([str(i), ip, f"{count:,}", f"{percentage:.2f}%"])
        
        src_table = Table(src_data, colWidths=[0.7*inch, 2.3*inch, 1.5*inch, 1.5*inch])
        src_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2ecc71')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey])
        ]))
        story.append(src_table)
        
        story.append(PageBreak())
        story.append(Paragraph("Top Destination IP Addresses", self.styles['SectionHeader']))
        story.append(Spacer(1, 0.2*inch))
        
        chart_buf = self.create_chart_image(data, 'top_destinations')
        img = Image(chart_buf, width=6*inch, height=4*inch)
        story.append(img)
        story.append(Spacer(1, 0.2*inch))
        
        # Top destinations table
        dst_data = [['Rank', 'IP Address', 'Packet Count', '% of Total']]
        for i, (ip, count) in enumerate(data['top_destinations'].most_common(10), 1):
            percentage = (count / data['total_packets']) * 100
            dst_data.append([str(i), ip, f"{count:,}", f"{percentage:.2f}%"])
        
        dst_table = Table(dst_data, colWidths=[0.7*inch, 2.3*inch, 1.5*inch, 1.5*inch])
        dst_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e74c3c')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey])
        ]))
        story.append(dst_table)
        
        if alerts:
            story.append(PageBreak())
            story.append(Paragraph("Security Alerts & Anomalies", self.styles['SectionHeader']))
            story.append(Spacer(1, 0.2*inch))
            
            alert_intro = Paragraph(
                f"<font color='red'><b>WARNING:</b> {len(alerts)} security alert(s) were detected during the monitoring period. "
                "These alerts indicate potential security threats or anomalous network behavior that require immediate attention.</font>",
                self.styles['Normal']
            )
            story.append(alert_intro)
            story.append(Spacer(1, 0.2*inch))
            
            # Display alerts
            for alert in alerts[-20:]:  # Show last 20 alerts
                alert_para = Paragraph(f"• {alert}", self.styles['Alert'])
                story.append(alert_para)
                story.append(Spacer(1, 0.1*inch))
        
        story.append(PageBreak())
        story.append(Paragraph("Security Recommendations", self.styles['SectionHeader']))
        story.append(Spacer(1, 0.2*inch))
        
        recommendations = [
            "Review the security alerts above and check whether each one is a real threat or a false positive.",
            "Look at the top source IPs and confirm they belong to expected users or devices on the network.",
            "If the same IP appears in multiple alerts, consider blocking it at the firewall.",
        ]
        
        for rec in recommendations:
            rec_para = Paragraph(rec, self.styles['Normal'])
            story.append(rec_para)
            story.append(Spacer(1, 0.15*inch))
        
        story.append(Spacer(1, 0.5*inch))
        footer_text = Paragraph(
            "<i>This report was automatically generated by the Network Traffic Analyzer tool. "
            "For questions or concerns, please contact your network security team.</i>",
            ParagraphStyle('footer', parent=self.styles['Normal'], 
                         fontSize=9, alignment=TA_CENTER, textColor=colors.grey)
        )
        story.append(footer_text)
        
        # Build PDF
        try:
            doc.build(story)
            print(f"✅ PDF report generated successfully: {output_path}")
            print(f"📊 Report includes:")
            print(f"   - {data['total_packets']:,} packets analyzed")
            print(f"   - {len(data['protocols'])} protocols detected")
            print(f"   - {len(alerts)} security alerts documented")
            print(f"   - Multiple visualization charts")
            return True
        except Exception as e:
            print(f"❌ Error generating PDF: {e}")
            return False


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Generate PDF report from network traffic data')
    parser.add_argument('--csv', default='live_packets.csv', help='Path to CSV file')
    parser.add_argument('--alerts', default='security_alerts.log', help='Path to alerts log')
    parser.add_argument('--output', default='network_traffic_report.pdf', help='Output PDF filename')
    
    args = parser.parse_args()
    
    print("\n" + "="*60)
    print("📄 Network Traffic Report Generator")
    print("="*60)
    print(f"📊 Reading data from: {args.csv}")
    print(f"⚠️  Reading alerts from: {args.alerts}")
    print(f"💾 Output file: {args.output}")
    print("="*60 + "\n")
    
    generator = NetworkTrafficReportGenerator(args.csv, args.alerts)
    success = generator.generate_report(args.output)
    
    if success:
        print(f"\n🎉 Report ready! Open {args.output} to view.\n")
    else:
        print("\n❌ Report generation failed. Check the error messages above.\n")