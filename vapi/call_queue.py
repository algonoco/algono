#!/usr/bin/env python3
"""
Algono Call Queue System
Manages 2-concurrency limit for Vapi outbound calls
Keeps pipeline full until all prospects contacted
"""

import json
import time
import requests
from datetime import datetime
from pathlib import Path

VAPI_API_KEY = "5bbb70bc-10b0-41cb-8f16-168b5c7e4fc6"
VAPI_BASE_URL = "https://api.vapi.ai"
ASSISTANT_ID = "39136214-e3d2-4862-9424-af5824a5ebba"
PHONE_NUMBER_ID = "35ba4e2d-fcf0-42b1-8985-60fa9ea328ae"

HEADERS = {
    "Authorization": f"Bearer {VAPI_API_KEY}",
    "Content-Type": "application/json"
}

class CallQueue:
    def __init__(self):
        self.prospects = []
        self.active_calls = {}
        self.completed_calls = []
        self.load_prospects()
        
    def normalize_prospect(self, p, batch):
        """Normalize prospect fields from different formats"""
        # Handle both batch formats
        normalized = {
            "batch": batch,
            "phone": p.get("phone"),
        }
        
        # Handle name field variations
        if "name" in p:
            normalized["name"] = p["name"]
        elif "company_name" in p:
            normalized["name"] = p["company_name"]
        else:
            normalized["name"] = "Unknown"
        
        # Handle contact field variations
        if "contact" in p:
            contact = p["contact"]
            normalized["contact_name"] = contact.get("name", "IT Manager")
            normalized["contact_title"] = contact.get("title", "IT Manager")
        elif "contact_name" in p:
            normalized["contact_name"] = p["contact_name"]
            normalized["contact_title"] = p.get("contact_title", "IT Manager")
        else:
            normalized["contact_name"] = "IT Manager"
            normalized["contact_title"] = "IT Manager"
        
        # Copy other useful fields
        normalized["industry"] = p.get("industry", "Unknown")
        normalized["location"] = p.get("location", "Unknown")
        normalized["employees"] = p.get("employees") or p.get("employee_count", "Unknown")
        
        return normalized
        
    def load_prospects(self):
        """Load all prospects from both batches and normalize"""
        base_path = Path(__file__).parent.parent / "prospecting"
        
        # Load batch 1 (raw list format with company_name/contact_name)
        try:
            with open(base_path / "prospects.json") as f:
                batch1 = json.load(f)
                if isinstance(batch1, list):
                    for p in batch1:
                        normalized = self.normalize_prospect(p, 1)
                        if normalized["phone"]:
                            self.prospects.append(normalized)
                print(f"✅ Batch 1: Loaded {len(self.prospects)} prospects")
        except Exception as e:
            print(f"⚠️ Error loading batch 1: {e}")
        
        # Load batch 2 (dict format with 'prospects' key)
        try:
            with open(base_path / "algono_prospects_batch_2.json") as f:
                batch2 = json.load(f)
                count_before = len(self.prospects)
                for p in batch2.get("prospects", []):
                    normalized = self.normalize_prospect(p, 2)
                    if normalized["phone"]:
                        self.prospects.append(normalized)
                print(f"✅ Batch 2: Loaded {len(self.prospects) - count_before} prospects")
        except Exception as e:
            print(f"⚠️ Error loading batch 2: {e}")
        
        print(f"✅ Total prospects ready to call: {len(self.prospects)}")
        
    def get_pending_prospects(self):
        """Get prospects not yet called"""
        called = {c["prospect"]["name"] for c in self.completed_calls}
        called.update({info["prospect"]["name"] for info in self.active_calls.values()})
        return [p for p in self.prospects if p["name"] not in called]
    
    def make_call(self, prospect):
        """Initiate a call to a prospect"""
        payload = {
            "assistantId": ASSISTANT_ID,
            "phoneNumberId": PHONE_NUMBER_ID,
            "customer": {
                "number": prospect["phone"],
                "name": prospect["contact_name"]
            }
        }
        
        try:
            response = requests.post(
                f"{VAPI_BASE_URL}/call",
                headers=HEADERS,
                json=payload,
                timeout=30
            )
            
            if response.status_code in [200, 201]:
                data = response.json()
                call_id = data.get("id")
                self.active_calls[call_id] = {
                    "prospect": prospect,
                    "started_at": datetime.now().isoformat(),
                    "status": "queued"
                }
                print(f"📞 Call {call_id} to {prospect['name']} ({prospect['phone']}) - {prospect['contact_name']}, {prospect['contact_title']}")
                return call_id
            else:
                print(f"❌ Failed to call {prospect['name']}: {response.status_code}")
                return None
        except Exception as e:
            print(f"❌ Error calling {prospect['name']}: {e}")
            return None
    
    def check_call_status(self, call_id):
        """Check status of an active call"""
        try:
            response = requests.get(
                f"{VAPI_BASE_URL}/call/{call_id}",
                headers=HEADERS,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                status = data.get("status")
                
                if status in ["ended", "failed", "canceled"]:
                    info = self.active_calls.pop(call_id)
                    info["ended_at"] = datetime.now().isoformat()
                    info["final_status"] = status
                    info["duration"] = data.get("duration", 0)
                    self.completed_calls.append(info)
                    print(f"✅ Call {call_id} completed - {info['prospect']['name']} ({status})")
                    return True
                else:
                    self.active_calls[call_id]["status"] = status
                    return False
            return False
        except Exception as e:
            print(f"⚠️ Error checking {call_id}: {e}")
            return False
    
    def print_status(self):
        """Print current queue status"""
        pending = len(self.get_pending_prospects())
        active = len(self.active_calls)
        completed = len(self.completed_calls)
        total = len(self.prospects)
        
        print(f"\n{'='*60}")
        print(f"QUEUE STATUS")
        print(f"{'='*60}")
        print(f"Pending:    {pending}/{total}")
        print(f"Active:     {active}/2")
        print(f"Completed:  {completed}/{total}")
        print(f"{'='*60}\n")
        
        if self.completed_calls:
            print("Recent completions:")
            for c in self.completed_calls[-3:]:
                p = c['prospect']
                print(f"  - {p['name']}: {c['final_status']} ({c.get('duration', 'N/A')}s)")
            print()
    
    def run(self):
        """Main loop - keep 2 calls active until all prospects contacted"""
        print("=" * 60)
        print("ALGONO CALL QUEUE SYSTEM - ENGAGED")
        print("2-Concurrency Management")
        print("HI HO SILVER, AWAY!")
        print("=" * 60)
        print()
        
        try:
            while True:
                # Check current active calls
                completed_now = []
                for call_id in list(self.active_calls.keys()):
                    if self.check_call_status(call_id):
                        completed_now.append(call_id)
                
                # Get pending prospects
                pending = self.get_pending_prospects()
                
                # Print status every iteration
                self.print_status()
                
                # Fill up to 2 concurrent calls
                calls_made = 0
                while len(self.active_calls) < 2 and pending and calls_made < 2:
                    prospect = pending.pop(0)
                    call_id = self.make_call(prospect)
                    if call_id:
                        calls_made += 1
                        time.sleep(1)  # Brief delay between calls
                
                # Check if complete
                if not pending and not self.active_calls:
                    print("\n" + "=" * 60)
                    print("🎉 ALL PROSPECTS CONTACTED!")
                    print("=" * 60)
                    print(f"\nTotal calls completed: {len(self.completed_calls)}")
                    self.print_status()
                    break
                
                # Wait before next check
                time.sleep(10)
                
        except KeyboardInterrupt:
            print("\n\n" + "=" * 60)
            print("⚠️  QUEUE STOPPED BY USER")
            print("=" * 60)
            self.print_status()

if __name__ == "__main__":
    queue = CallQueue()
    queue.run()
