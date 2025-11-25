Addis Ababa City Pathfinding System — README


This project is a Flask-based pathfinding application that visualizes optimal routes between major locations in Addis Ababa using UCS, DFS, or A* algorithms.
It integrates:

Leaflet.js interactive map

Custom city graph with 9 key areas (Meskel Square, Bole, Piazza, Megenagna, Airport, Arada, Merkato, CMC, Bole Michael)

Constraint handling (traffic, road conditions, invalid inputs, duplicated start-end, etc.)

Multiple-path detection

Dynamic visual highlighting of the chosen route

Users can select start and goal locations, choose the algorithm, and view a detailed route on the map including distance and warnings.

Features
1. Interactive Leaflet Map

Displays Addis Ababa with location markers.

Routes are drawn dynamically.

Colors reflect road condition quality (green = good, yellow = moderate, red = poor).

2. Three Algorithms

UCS (Uniform Cost Search) → finds the optimal shortest path.

DFS (Depth First Search) → explores deep but not always optimal.

A* → intelligent heuristic pathfinding.

3. Real-World Inspired Graph

9 districts modeled using approximate travel distances.

Fully bidirectional network.

4. Full Constraint Handling

The app intelligently detects and responds to constraints:

a. Same Start & Goal

If a user selects the same location for both fields:

“You are already at your destination.”

b. Invalid or Unknown Locations

If a location does not exist in the graph:

The system reports the error and lists all valid locations.

c. Multiple Optimal Paths

If two or more shortest paths exist:

All are listed in the result panel.

One is highlighted as the primary recommended route.

Alternative paths appear in a different color on the map.

d. Road Condition Assessment

Road quality is encoded as:

Condition	Meaning	Color
Good	smooth road	 green
Moderate	average conditions	yellow
Poor	rough/bad condition	 red

If a poor road exists along the route, a warning appears.

e. Traffic Level Simulation

Major hotspots:

Meskel Square

Megenagna

Bole Michael

Piazza

If the trip starts from or passes through these:

“High traffic expected at <location>.”

Project Structure
project/
│
├── app.py                 # Main Flask backend
├── static/
│     ├── css/style.css    # Styling
│     ├── js/app.js        # Frontend logic + Leaflet route drawing
│     ├── libs/leaflet.js  # Map rendering
│
├── templates/
│     └── index.html       # UI with select menus, map container, results panel
│
└── README.md              # This document

How It Works
1. City Graph

The graph defines the city's network:

self.graph = {
    'Meskel Square': {'Bole': 5, 'Piazza': 4, 'Megenagna': 3},
    'Bole': {'Meskel Square': 5, 'Airport': 3, 'Bole Michael': 4},
    ...
}


Distances measured in km (approx).

2. Road Conditions
self.road_conditions = {
    ('Meskel Square','Bole'): 'good',
    ('Piazza','Arada'): 'poor',
    ...
}


Bidirectional conditions are normalized internally.

3. Traffic Hotspots
self.traffic_hotspots = {
    "Meskel Square", "Megenagna", "Bole Michael", "Piazza"
}


If your path touches these, you get a yellow warning.

4. Algorithms Implemented
UCS

Prioritizes minimal cumulative distance.

DFS

Explores deep routes; may not be optimal.

A*

Uses a straight-line heuristic (approximation for this project).

Running the Project
Prerequisites

Python 3.8+

pip installed

1. Install Dependencies

Open your terminal/CMD inside the project folder:

pip install flask

2. Start the Flask Server
python app.py

3. Open the App

Visit:

http://127.0.0.1:5000


You will see the interface with:

Start location dropdown

Goal location dropdown

Algorithm selector

"Find Path" button

Leaflet.js interactive map

Constraint notifications

Path summary (distance, nodes, algorithm used)

How the Constraints Are Displayed in the App
✓ Same Start/Goal

Displayed as:

“You are already at your destination.”

⚠️ Invalid Location

Displayed in a yellow warning box:

“Unknown location entered. Valid locations are: ...”

ↆ Multiple Optimal Paths

Shown in a list under “Path Found”

Map highlights:

main path = blue

alternatives = grey or dashed

● Road Condition Warnings

If a poor road exists:

“Warning: This route includes poor road segments.”

The map displays:

🟢 good segments

🟡 moderate

🔴 poor

🚦 Traffic Hotspot Alerts

If the route begins or passes through a high-traffic node:

“High traffic expected at Megenagna.”

Displayed above the result panel.

Leaflet.js Integration

The app uses Leaflet.js:

<link rel="stylesheet" href="/static/libs/leaflet.css" />
<script src="/static/libs/leaflet.js"></script>


Routes are drawn using:

L.polyline(pathCoordinates, {color: "blue"}).addTo(map);


Markers added for:

Meskel Square

Bole

Piazza

Megenagna

Airport

Arada

Merkato

CMC

Bole Michael

Coordinates can be updated for more accuracy.
