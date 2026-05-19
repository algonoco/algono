#!/usr/bin/env python3
"""
Algono Multi-Channel Dashboard
Unified tracking for all 3 outreach channels
"""

import json
from datetime import datetime
from pathlib import Path

class MultiChannelDashboard:
    def __init__(self):
        self.channels = {
            "A": "Voice + Voicemail",
            "B": "LinkedIn + Direct Mobile", 
            "C": "Email/Texter"
        }
        self.stats_file = Path(__file__).parent / "campaign_stats.json"
        self.load_stats()
    
    def load_stats(self):
        """Load or initialize campaign stats"""
        if self.stats_file.exists():
            with open(self.stats_file) as f:
                self.stats = json.load(f)
        else:
            self.stats = {
                "campaign_start": datetime.now().isoformat(),
                "channels": {
                    "A": {
                        "name": "Voice + Voicemail",
                        "calls_made": 100,
                        "voicemails_left": 100,
                        "live_answers": 0,
                        "conversations": 0,
                        "texts_sent": 0,
                        "inbound_callbacks": 0,
                        "scans_booked": 0,
                        "sales_closed": 0
                    },
                    "B": {
                        "name": "LinkedIn + Direct Mobile",
                        "connection_requests_sent": 5,
                        "connections_accepted": 0,
                        "warm_calls_made": 0,
                        "conversations": 0,
                        "scans_booked": 0,
                        "sales_closed": 0
                    },
                    "C": {
                        "name": "Email/Texter",
                        "emails_sent": 0,
                        "emails_opened": 0,
                        "replies_received": 0,
                        "commands_run": 0,
                        "scans_booked": 0,
                        "sales_closed": 0
                    }
                },
                "totals": {
                    "revenue": 0,
                    "target": 800,
                    "prospects_contacted": 100,
                    "conversations": 0
                }
            }
    
    def save_stats(self):
        """Save stats to file"""
        with open(self.stats_file, 'w') as f:
            json.dump(self.stats, f, indent=2)
    
    def print_dashboard(self):
        """Print formatted dashboard"""
        print("="*80)
        print("ALGONO MULTI-CHANNEL OUTREACH DASHBOARD")
        print(f"Updated: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        print("="*80)
        print()
        
        # Channel A
        a = self.stats["channels"]["A"]
        print("📞 CHANNEL A: VOICE + VOICEMAIL")
        print("-"*40)
        print(f"  Calls made:        {a['calls_made']}")
        print(f"  Voicemails left:   {a['voicemails_left']}")
        print(f"  Live answers:      {a['live_answers']}")
        print(f"  Conversations:     {a['conversations']}")
        print(f"  Inbound callbacks: {a['inbound_callbacks']}")
        print(f"  Scans booked:      {a['scans_booked']}")
        print(f"  Sales closed:      {a['sales_closed']} (${a['sales_closed']*400})")
        print()
        
        # Channel B
        b = self.stats["channels"]["B"]
        print("💼 CHANNEL B: LINKEDIN + DIRECT MOBILE")
        print("-"*40)
        print(f"  Connection requests:  {b['connection_requests_sent']}")
        print(f"  Connections accepted: {b['connections_accepted']}")
        print(f"  Warm calls made:      {b['warm_calls_made']}")
        print(f"  Conversations:        {b['conversations']}")
        print(f"  Scans booked:         {b['scans_booked']}")
        print(f"  Sales closed:         {b['sales_closed']} (${b['sales_closed']*400})")
        print()
        
        # Channel C
        c = self.stats["channels"]["C"]
        print("📧 CHANNEL C: EMAIL/TEXTER")
        print("-"*40)
        print(f"  Emails sent:      {c['emails_sent']}")
        print(f"  Emails opened:    {c['emails_opened']}")
        print(f"  Replies received: {c['replies_received']}")
        print(f"  Commands run:     {c['commands_run']}")
        print(f"  Scans booked:     {c['scans_booked']}")
        print(f"  Sales closed:     {c['sales_closed']} (${c['sales_closed']*400})")
        print()
        
        # Totals
        t = self.stats["totals"]
        revenue = a['sales_closed']*400 + b['sales_closed']*400 + c['sales_closed']*400
        progress = (revenue / t['target']) * 100
        
        print("="*80)
        print("TOTALS")
        print("="*80)
        print(f"  Revenue:      ${revenue} / ${t['target']} ({progress:.1f}%)")
        print(f"  Target:       {t['target']/400:.0f} sales at $400")
        print(f"  Prospects:    {t['prospects_contacted']}")
        print(f"  Conversations: {a['conversations'] + b['conversations']}")
        print()
        
        if revenue >= t['target']:
            print("🎉 ES**CAPE VELOCITY ACHIEVED! 🎉")
        else:
            remaining = t['target'] - revenue
            needed = remaining / 400
            print(f"📊 Need ${remaining:.0f} more ({needed:.0f} sales) for escape velocity")
        
        print("="*80)

if __name__ == "__main__":
    dashboard = MultiChannelDashboard()
    dashboard.print_dashboard()
    
    print("\n💡 TIP: Run this dashboard daily to track progress")
    print("   python3 multi_channel_dashboard.py")
