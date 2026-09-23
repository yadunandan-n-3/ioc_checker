import json
import folium
import requests
from folium.plugins import MarkerCluster

def create_threat_map():
    # 1. Load your existing scan data
    try:
        with open("advanced_report.json", "r") as f:
            data = json.load(f)
    except FileNotFoundError:
        print("[!] Error: run your reputation checker first to create advanced_report.json")
        return

    # 2. Initialize the World Map (Dark Theme)
    m = folium.Map(location=[20, 0], zoom_start=2, tiles="CartoDB dark_matter")
    marker_cluster = MarkerCluster().add_to(m)

    print("[*] Generating map markers...")

    for entry in data:
        ip = entry.get('ip')
        verdict = entry.get('verdict')
        
        # Get coordinates for the map
        try:
            geo_req = requests.get(f"http://ip-api.com/json/{ip}").json()
            lat, lon = geo_req.get('lat'), geo_req.get('lon')
            
            if lat and lon:
                color = "red" if verdict == "MALICIOUS" else "green"
                icon_type = "info-sign" if verdict == "MALICIOUS" else "ok-circle"
                
                popup_text = f"<b>IP:</b> {ip}<br><b>Status:</b> {verdict}<br><b>ISP:</b> {entry.get('isp')}"
                
                folium.Marker(
                    location=[lat, lon],
                    popup=folium.Popup(popup_text, max_width=300),
                    tooltip=f"{ip} ({verdict})",
                    icon=folium.Icon(color=color, icon=icon_type)
                ).add_to(marker_cluster)
        except:
            continue

    # 3. Save the Map
    m.save("threat_map.html")
    print("[+] Success! Created 'threat_map.html'")

if __name__ == "__main__":
    create_threat_map()
