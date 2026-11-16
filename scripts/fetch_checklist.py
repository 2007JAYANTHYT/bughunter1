#!/usr/bin/env python3
"""
Fetch checklists from https://checklist.hackwithsingh.com/
This script needs to be run locally since the site may be blocked from the container.
"""

import requests
from bs4 import BeautifulSoup
import json
import os
from pathlib import Path

def fetch_checklist():
    """Fetch all checklists from the website"""
    url = "https://checklist.hackwithsingh.com/"

    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
    except Exception as e:
        print(f"Failed to fetch: {e}")
        return None

    soup = BeautifulSoup(response.text, 'html.parser')

    # Extract all checklist items - structure depends on the site
    # This is a generic extractor - adjust based on actual HTML structure
    checklists = {}

    # Try to find checklist categories
    for section in soup.find_all('section'):
        category = section.find(['h1', 'h2', 'h3'])
        if category:
            cat_name = category.get_text(strip=True)
            items = []
            for li in section.find_all('li'):
                items.append(li.get_text(strip=True))
            if items:
                checklists[cat_name] = items

    return checklists


def save_checklists(checklists: dict, output_dir: str):
    """Save checklists as JSON files"""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    for category, items in checklists.items():
        filename = category.lower().replace(' ', '_').replace('/', '_') + '.json'
        filepath = output_path / filename
        with open(filepath, 'w') as f:
            json.dump({
                'category': category,
                'items': items
            }, f, indent=2)
        print(f"Saved {len(items)} items to {filepath}")

    # Also create a master checklist
    master_path = output_path / "master_checklist.json"
    with open(master_path, 'w') as f:
        json.dump(checklists, f, indent=2)
    print(f"Saved master checklist to {master_path}")


if __name__ == "__main__":
    print("Fetching checklists from https://checklist.hackwithsingh.com/")
    checklists = fetch_checklist()

    if checklists:
        save_checklists(checklists, "config/checklists/hackwithsingh")
        print("Done!")
    else:
        print("Failed to fetch checklists")