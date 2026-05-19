#!/usr/bin/env python3
"""
Algono Email/Texter Campaign System (Channel C)
Async outreach for prospects without direct mobile numbers
"""

import json
import csv
from datetime import datetime
from pathlib import Path

class EmailCampaign:
    def __init__(self):
        self.templates = {
            "subject": "Quick security win for {company} IT",
            
            "body": """Hi {first_name},

Quick one - free 10-min PowerShell scan finds dormant god-mode accounts in your Microsoft 365 (ex-employees, interns, contractors with standing admin access).

No email signup needed. No SaaS. No data collected. You run it yourself on your machine.

Free scan command:
irm https://raw.githubusercontent.com/algonoco/algono/main/prontoso/Scan-EntraPrivilegedUsers.ps1 | iex

Takes 5-10 minutes. Results stay on your machine. We don't phone home, don't collect data.

If it finds issues, $400 one-time toolkit fixes them. Buy once, use until it breaks.

Curious? Hit reply or check algono.co

- Algono
https://algono.co
""",
            
            "followup": """{first_name},

Following up on the PowerShell scanner I mentioned.

Quick reminder:
• One command finds god-mode accounts in your M365
• Run it locally, results stay on your machine  
• Free scan, $400 one-time if you want the fix
• Visit algono.co or just run the command below

irm https://raw.githubusercontent.com/algonoco/algono/main/prontoso/Scan-EntraPrivilegedUsers.ps1 | iex

What do you think? Worth 10 minutes?

- Algono
"""
        }
        
        self.prospects_file = Path(__file__).parent.parent / "prospecting" / "email_prospects.csv"
        
    def personalize(self, template, prospect):
        """Personalize template with prospect data"""
        first_name = prospect.get("contact_name", "").split()[0] if prospect.get("contact_name") else "IT Manager"
        company = prospect.get("company_name", prospect.get("name", "your company"))
        
        return template.format(
            first_name=first_name,
            company=company
        )
    
    def generate_email(self, prospect):
        """Generate personalized email for prospect"""
        subject = self.personalize(self.templates["subject"], prospect)
        body = self.personalize(self.templates["body"], prospect)
        
        return {
            "to": prospect.get("email"),
            "subject": subject,
            "body": body,
            "prospect": prospect,
            "generated_at": datetime.now().isoformat()
        }
    
    def generate_followup(self, prospect):
        """Generate follow-up email"""
        first_name = prospect.get("contact_name", "").split()[0] if prospect.get("contact_name") else "IT Manager"
        body = self.templates["followup"].format(first_name=first_name)
        
        return {
            "to": prospect.get("email"),
            "subject": "Re: Quick security win for your IT",
            "body": body,
            "prospect": prospect,
            "generated_at": datetime.now().isoformat()
        }
    
    def export_campaign_csv(self, prospects, output_file):
        """Export campaign to CSV for mail merge"""
        rows = []
        
        for i, p in enumerate(prospects):
            email = self.generate_email(p)
            rows.append({
                "send_order": i + 1,
                "to_email": email["to"],
                "subject": email["subject"],
                "body": email["body"].replace('"', '""'),  # Escape quotes for CSV
                "company": p.get("company_name", p.get("name", "")),
                "contact": p.get("contact_name", ""),
                "status": "ready_to_send",
                "sent_at": "",
                "opened": "",
                "replied": ""
            })
        
        with open(output_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)
        
        return output_file, len(rows)
    
    def print_email_preview(self, prospect):
        """Print formatted email preview"""
        email = self.generate_email(prospect)
        
        print("="*70)
        print("EMAIL PREVIEW")
        print("="*70)
        print(f"To: {email['to']}")
        print(f"Subject: {email['subject']}")
        print("-"*70)
        print(email['body'])
        print("="*70)

if __name__ == "__main__":
    # Demo with sample
    campaign = EmailCampaign()
    
    sample = {
        "company_name": "TechCorp Inc",
        "contact_name": "John Smith",
        "email": "john.smith@techcorp.com"
    }
    
    campaign.print_email_preview(sample)
    print("\nEmail campaign system ready!")
    print("\nUsage:")
    print("  from campaigns.email_campaign import EmailCampaign")
    print("  campaign = EmailCampaign()")
    print("  email = campaign.generate_email(prospect)")
