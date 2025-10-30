import json

# Load bundle.json
with open('bundle.json', 'r', encoding='utf-8-sig') as f:
    data = json.load(f)

# Define the new organized names for ISOs
iso_renames = {
    # Windows OSes
    "Windows 11 Pro 24H2 (Stock + Modded)": "01 - OS - Windows 11 Pro 24H2 (Modded - No TPM Required)",
    "Windows 10 Pro 22H2 (Stock OEM)": "02 - OS - Windows 10 Pro 22H2 (Official)",
    "Windows 11 Enterprise LTSC 2024": "03 - OS - Windows 11 Enterprise LTSC 2024",
    "Tiny11": "04 - OS - Tiny11 (Lightweight Win11)",
    "Live11": "05 - OS - Live11 (Portable Win11)",
    
    # Linux OSes
    "Kali Linux": "06 - OS - Kali Linux 2025.3 (Penetration Testing)",
    "Linux Mint 22.2 Cinnamon": "07 - OS - Linux Mint 22.1 (Beginner Friendly)",
    "Fedora Workstation 42": "08 - OS - Fedora 42 Workstation",
    "Tails": "09 - OS - Tails (Privacy/Anonymous)",
    
    # Tool ISOs
    "GParted Live": "10 - TOOL - GParted Live (Partition Editor)",
    "Hiren's Boot PE": "11 - TOOL - Hiren's BootCD PE (Recovery Suite)",
    "Clonezilla": "12 - TOOL - Clonezilla (Disk Cloning/Backup)",
    "Rescuezilla": "13 - TOOL - Rescuezilla (Easy Backup/Restore)",
    "Memtest86+": "14 - TOOL - Memtest86+ (RAM Testing)",
}

# Update names
for item in data['items']:
    if item['name'] in iso_renames:
        old_name = item['name']
        item['name'] = iso_renames[old_name]
        print(f"Renamed: {old_name} -> {item['name']}")
    
    # Also clarify edition notes
    if 'Win11Pro' in str(item.get('resolve', {})):
        if 'fido_with_mods' in str(item.get('resolve', {})):
            item['resolve']['note'] = "Downloads official Win11 Pro, creates modded version with TPM/SecureBoot/RAM bypasses. Both ISOs saved."
        elif 'fido_automated' in str(item.get('resolve', {})):
            if 'Win11' in item['resolve'].get('edition', ''):
                item['resolve']['note'] = "Official Microsoft Windows 11 Pro - requires TPM 2.0, SecureBoot, 4GB RAM"
            elif 'Win10' in item['resolve'].get('edition', ''):
                item['resolve']['note'] = "Official Microsoft Windows 10 Pro - no TPM required"

# Save back to bundle.json with proper formatting
with open('bundle.json', 'w', encoding='utf-8') as f:
    json.dump(data, f, indent=4, ensure_ascii=False)

print(f"\nDone! Renamed {len([k for k in iso_renames if k in [i['name'] for i in data['items']]])} items")
print(f"Total items in bundle: {len(data['items'])}")
