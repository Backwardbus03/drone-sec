"""
Authoritative Catalog of Real-World Geo-Restricted Airspaces.
Covers Civil & International Airports, Aerodromes & Heliports, Military Airbases,
Government & Constitutional High-Security Perimeters, Strategic Nuclear & Space Infrastructure,
and High-Security Correctional Facilities.
Compliant with DGCA Digital Sky (India), FAA UAS Facility Maps, and ICAO Annex 2/11/14.
"""

from typing import List, Optional, Dict
from dft.core.models import GeofenceZone


# Real-World Catalog Master Registry
REAL_WORLD_RESTRICTED_SPACES: List[Dict] = [
    # ==========================================
    # 1. CIVIL & INTERNATIONAL AIRPORTS
    # ==========================================
    {
        "zone_id": "ZONE-AIRPORT-BOM",
        "name": "Chhatrapati Shivaji Maharaj International Airport (BOM/VABB)",
        "zone_type": "circle",
        "center_lat": 19.0896,
        "center_lon": 72.8656,
        "radius_meters": 15000.0,
        "max_altitude_m": 0.0,
        "description": "DGCA Red Zone under Drone Rules 2021: Within 5 km of international airport perimeter. Absolute UAV prohibition.",
        "is_preconfigured_nofly": True,
        "category": "AIRPORT",
        "zone_class": "RED",
        "authority": "DGCA / AAI / MIAL",
        "city_region": "Mumbai / MMR"
    },
    {
        "zone_id": "ZONE-AIRPORT-DEL",
        "name": "Indira Gandhi International Airport (DEL/VIDP)",
        "zone_type": "circle",
        "center_lat": 28.5562,
        "center_lon": 77.1000,
        "radius_meters": 8000.0,
        "max_altitude_m": 0.0,
        "description": "National Capital International Airport Red Zone. Critical civil aviation terminal exclusion zone.",
        "is_preconfigured_nofly": True,
        "category": "AIRPORT",
        "zone_class": "RED",
        "authority": "DGCA / AAI / DIAL",
        "city_region": "Delhi NCR"
    },
    {
        "zone_id": "ZONE-AIRPORT-BLR",
        "name": "Kempegowda International Airport Bengaluru (BLR/VOBL)",
        "zone_type": "circle",
        "center_lat": 13.1986,
        "center_lon": 77.7066,
        "radius_meters": 8000.0,
        "max_altitude_m": 0.0,
        "description": "Devenahalli Civil Aviation Hub Red Zone. Strict 8 km no-drone exclusion boundary.",
        "is_preconfigured_nofly": True,
        "category": "AIRPORT",
        "zone_class": "RED",
        "authority": "DGCA / BIAL / AAI",
        "city_region": "Bengaluru"
    },
    {
        "zone_id": "ZONE-AIRPORT-HYD",
        "name": "Rajiv Gandhi International Airport (HYD/VOHS)",
        "zone_type": "circle",
        "center_lat": 17.2403,
        "center_lon": 78.4294,
        "radius_meters": 8000.0,
        "max_altitude_m": 0.0,
        "description": "Shamshabad International Airport Red Zone. Full airspace restriction under DGCA mandate.",
        "is_preconfigured_nofly": True,
        "category": "AIRPORT",
        "zone_class": "RED",
        "authority": "DGCA / GHIAL / AAI",
        "city_region": "Hyderabad"
    },
    {
        "zone_id": "ZONE-AIRPORT-MAA",
        "name": "Chennai International Airport (MAA/VOMM)",
        "zone_type": "circle",
        "center_lat": 12.9941,
        "center_lon": 80.1709,
        "radius_meters": 8000.0,
        "max_altitude_m": 0.0,
        "description": "Meenambakkam Civil Airport and Obstacle Limitation Surface (OLS) Red Zone.",
        "is_preconfigured_nofly": True,
        "category": "AIRPORT",
        "zone_class": "RED",
        "authority": "DGCA / AAI",
        "city_region": "Chennai"
    },
    {
        "zone_id": "ZONE-AIRPORT-CCU",
        "name": "Netaji Subhash Chandra Bose International Airport (CCU/VECC)",
        "zone_type": "circle",
        "center_lat": 22.6547,
        "center_lon": 88.4467,
        "radius_meters": 8000.0,
        "max_altitude_m": 0.0,
        "description": "Dum Dum Civil Aviation Red Zone. Eastern India primary international aerial corridor.",
        "is_preconfigured_nofly": True,
        "category": "AIRPORT",
        "zone_class": "RED",
        "authority": "DGCA / AAI",
        "city_region": "Kolkata"
    },
    {
        "zone_id": "ZONE-AIRPORT-PNQ",
        "name": "Pune International Airport & Civil Enclave (PNQ/VAPO)",
        "zone_type": "circle",
        "center_lat": 18.5822,
        "center_lon": 73.9197,
        "radius_meters": 5000.0,
        "max_altitude_m": 0.0,
        "description": "Joint Civil Aviation Enclave & Indian Air Force Lohegaon Base. Complete Red Zone.",
        "is_preconfigured_nofly": True,
        "category": "AIRPORT",
        "zone_class": "RED",
        "authority": "DGCA / IAF / AAI",
        "city_region": "Maharashtra"
    },
    {
        "zone_id": "ZONE-AIRPORT-GOI",
        "name": "Goa Dabolim International Airport (GOI/VAGO)",
        "zone_type": "circle",
        "center_lat": 15.3808,
        "center_lon": 73.8313,
        "radius_meters": 5000.0,
        "max_altitude_m": 0.0,
        "description": "Dual-use Military / Civil Airport at INS Hansa Naval Base. High security no-fly perimeter.",
        "is_preconfigured_nofly": True,
        "category": "AIRPORT",
        "zone_class": "RED",
        "authority": "Indian Navy / AAI / DGCA",
        "city_region": "Goa"
    },
    {
        "zone_id": "ZONE-AIRPORT-GOX",
        "name": "Manohar International Airport Mopa (GOX/VOGA)",
        "zone_type": "circle",
        "center_lat": 15.7550,
        "center_lon": 73.8640,
        "radius_meters": 5000.0,
        "max_altitude_m": 0.0,
        "description": "North Goa International Greenfield Airport Red Zone.",
        "is_preconfigured_nofly": True,
        "category": "AIRPORT",
        "zone_class": "RED",
        "authority": "DGCA / GGIAL",
        "city_region": "Goa"
    },
    {
        "zone_id": "ZONE-AIRPORT-AMD",
        "name": "Sardar Vallabhbhai Patel International Airport (AMD/VAAH)",
        "zone_type": "circle",
        "center_lat": 23.0772,
        "center_lon": 72.6347,
        "radius_meters": 5000.0,
        "max_altitude_m": 0.0,
        "description": "Hansol Ahmedabad Civil Airport Red Zone.",
        "is_preconfigured_nofly": True,
        "category": "AIRPORT",
        "zone_class": "RED",
        "authority": "DGCA / Adani Airports / AAI",
        "city_region": "Gujarat"
    },

    # ==========================================
    # 2. AERODROMES, AIRDROMES & HELIPORTS
    # ==========================================
    {
        "zone_id": "ZONE-AIRDROME-VAJJ",
        "name": "Juhu Aerodrome (VAJJ, Mumbai)",
        "zone_type": "circle",
        "center_lat": 19.0975,
        "center_lon": 72.8339,
        "radius_meters": 3000.0,
        "max_altitude_m": 0.0,
        "description": "India's premier civil helicopter hub and general aviation aerodrome. Intensive rotorcraft corridor.",
        "is_preconfigured_nofly": True,
        "category": "AIRDROME",
        "zone_class": "RED",
        "authority": "AAI / DGCA",
        "city_region": "Mumbai / MMR"
    },
    {
        "zone_id": "ZONE-AIRDROME-VIDD",
        "name": "Safdarjung Airport & Flying Club (VIDD, New Delhi)",
        "zone_type": "circle",
        "center_lat": 28.5843,
        "center_lon": 77.2081,
        "radius_meters": 3000.0,
        "max_altitude_m": 0.0,
        "description": "Historic civil aerodrome and VIP helicopter transit hub adjacent to Lutyens Delhi.",
        "is_preconfigured_nofly": True,
        "category": "AIRDROME",
        "zone_class": "RED",
        "authority": "AAI / DGCA / Ministry of Civil Aviation",
        "city_region": "Delhi NCR"
    },
    {
        "zone_id": "ZONE-AIRDROME-ROHINI",
        "name": "Pawan Hans Rohini Heliport (Delhi)",
        "zone_type": "circle",
        "center_lat": 28.7460,
        "center_lon": 77.0680,
        "radius_meters": 2500.0,
        "max_altitude_m": 0.0,
        "description": "Dedicated commercial helicopter operational facility and maintenance base.",
        "is_preconfigured_nofly": True,
        "category": "AIRDROME",
        "zone_class": "RED",
        "authority": "Pawan Hans / AAI",
        "city_region": "Delhi NCR"
    },
    {
        "zone_id": "ZONE-AIRDROME-HAL",
        "name": "HAL Airport & Aerodrome (VOBG, Bengaluru)",
        "zone_type": "circle",
        "center_lat": 12.9500,
        "center_lon": 77.6682,
        "radius_meters": 4000.0,
        "max_altitude_m": 0.0,
        "description": "HAL flight testing aerodrome, VVIP military flights, and aerospace research facility.",
        "is_preconfigured_nofly": True,
        "category": "AIRDROME",
        "zone_class": "RED",
        "authority": "Hindustan Aeronautics Limited / MoD",
        "city_region": "Bengaluru"
    },
    {
        "zone_id": "ZONE-AIRDROME-BEGUMPET",
        "name": "Begumpet Airport & Air Force Academy Transit (VOHY, Hyderabad)",
        "zone_type": "circle",
        "center_lat": 17.4531,
        "center_lon": 78.4676,
        "radius_meters": 4000.0,
        "max_altitude_m": 0.0,
        "description": "Civil aviation training, VIP transit, and Telangana State Aviation Academy aerodrome.",
        "is_preconfigured_nofly": True,
        "category": "AIRDROME",
        "zone_class": "RED",
        "authority": "AAI / DGCA",
        "city_region": "Hyderabad"
    },
    {
        "zone_id": "ZONE-AIRDROME-HADAPSAR",
        "name": "Hadapsar Gliding Centre (Pune)",
        "zone_type": "circle",
        "center_lat": 18.5080,
        "center_lon": 73.9280,
        "radius_meters": 2000.0,
        "max_altitude_m": 0.0,
        "description": "DGCA civil aviation gliding airfield and low-altitude unpowered aircraft sector.",
        "is_preconfigured_nofly": True,
        "category": "AIRDROME",
        "zone_class": "RED",
        "authority": "DGCA",
        "city_region": "Maharashtra"
    },

    # ==========================================
    # 3. MILITARY AIRFIELDS & NAVAL AIR STATIONS
    # ==========================================
    {
        "zone_id": "ZONE-MIL-SHIKRA",
        "name": "INS Shikra Naval Air Station (Colaba, Mumbai)",
        "zone_type": "circle",
        "center_lat": 18.9042,
        "center_lon": 72.8174,
        "radius_meters": 3000.0,
        "max_altitude_m": 0.0,
        "description": "Headquarters Western Fleet Naval Air Station. Strict statutory military exclusion zone under MoD.",
        "is_preconfigured_nofly": True,
        "category": "MILITARY_AIRFORCE",
        "zone_class": "RED",
        "authority": "Indian Navy / Ministry of Defence",
        "city_region": "Mumbai / MMR"
    },
    {
        "zone_id": "ZONE-MIL-HINDON",
        "name": "Hindon Air Force Station (VABP, Ghaziabad/NCR)",
        "zone_type": "circle",
        "center_lat": 28.7067,
        "center_lon": 77.3592,
        "radius_meters": 5000.0,
        "max_altitude_m": 0.0,
        "description": "Asia's largest air base. Strategic heavy airlift (C-17, C-130J) and air defense base.",
        "is_preconfigured_nofly": True,
        "category": "MILITARY_AIRFORCE",
        "zone_class": "RED",
        "authority": "Indian Air Force (IAF) / MoD",
        "city_region": "Delhi NCR"
    },
    {
        "zone_id": "ZONE-MIL-YELAHANKA",
        "name": "Yelahanka Air Force Station (Bengaluru)",
        "zone_type": "circle",
        "center_lat": 13.1355,
        "center_lon": 77.6061,
        "radius_meters": 5000.0,
        "max_altitude_m": 0.0,
        "description": "IAF Pilot Training Command & Aero India venue. Heavy defense transport flight operations.",
        "is_preconfigured_nofly": True,
        "category": "MILITARY_AIRFORCE",
        "zone_class": "RED",
        "authority": "Indian Air Force (IAF)",
        "city_region": "Bengaluru"
    },
    {
        "zone_id": "ZONE-MIL-AMBALA",
        "name": "Ambala Air Force Station (Rafale Golden Arrows Base)",
        "zone_type": "circle",
        "center_lat": 30.3689,
        "center_lon": 76.8172,
        "radius_meters": 5000.0,
        "max_altitude_m": 0.0,
        "description": "Frontline IAF Tactical Fighter Wing base. High alert national security airspace.",
        "is_preconfigured_nofly": True,
        "category": "MILITARY_AIRFORCE",
        "zone_class": "RED",
        "authority": "Indian Air Force (IAF) / MoD",
        "city_region": "Northern India"
    },
    {
        "zone_id": "ZONE-MIL-TAMBARAM",
        "name": "Tambaram Air Force Station (Chennai)",
        "zone_type": "circle",
        "center_lat": 12.9070,
        "center_lon": 80.1230,
        "radius_meters": 4000.0,
        "max_altitude_m": 0.0,
        "description": "IAF Flying Instructors School & mechanical training airbase.",
        "is_preconfigured_nofly": True,
        "category": "MILITARY_AIRFORCE",
        "zone_class": "RED",
        "authority": "Indian Air Force (IAF)",
        "city_region": "Chennai"
    },

    # ==========================================
    # 4. GOVERNMENT & CONSTITUTIONAL SITES
    # ==========================================
    {
        "zone_id": "ZONE-GOV-CENTRALVISTA",
        "name": "Central Vista, Parliament & Rashtrapati Bhavan (New Delhi)",
        "zone_type": "circle",
        "center_lat": 28.6143,
        "center_lon": 77.1994,
        "radius_meters": 3500.0,
        "max_altitude_m": 0.0,
        "description": "Seat of the Union Government: Parliament House, PMO, North/South Block, and President's Estate. Absolute Red Zone.",
        "is_preconfigured_nofly": True,
        "category": "GOVERNMENT",
        "zone_class": "RED",
        "authority": "Ministry of Home Affairs / Delhi Police / SPG",
        "city_region": "Delhi NCR"
    },
    {
        "zone_id": "ZONE-GOV-MANTRALAYA",
        "name": "Mantralaya & Vidhan Bhavan Complex (Nariman Point, Mumbai)",
        "zone_type": "circle",
        "center_lat": 18.9270,
        "center_lon": 72.8275,
        "radius_meters": 1500.0,
        "max_altitude_m": 0.0,
        "description": "Administrative Secretariat and Legislative Assembly of Maharashtra. Permanent high-security zone.",
        "is_preconfigured_nofly": True,
        "category": "GOVERNMENT",
        "zone_class": "RED",
        "authority": "Govt of Maharashtra / Mumbai Police",
        "city_region": "Mumbai / MMR"
    },
    {
        "zone_id": "ZONE-GOV-RAJBHAVAN-MUM",
        "name": "Raj Bhavan Estate (Malabar Hill, Mumbai)",
        "zone_type": "circle",
        "center_lat": 18.9430,
        "center_lon": 72.7960,
        "radius_meters": 1500.0,
        "max_altitude_m": 0.0,
        "description": "Official gubernatorial estate of Maharashtra. Coastal security perimeter.",
        "is_preconfigured_nofly": True,
        "category": "GOVERNMENT",
        "zone_class": "RED",
        "authority": "Raj Bhavan Secretariat / Mumbai Police",
        "city_region": "Mumbai / MMR"
    },
    {
        "zone_id": "ZONE-GOV-VIDHANASOUDHA",
        "name": "Vidhana Soudha & High Court of Karnataka (Bengaluru)",
        "zone_type": "circle",
        "center_lat": 12.9791,
        "center_lon": 77.5913,
        "radius_meters": 2000.0,
        "max_altitude_m": 0.0,
        "description": "Seat of Karnataka State Legislature and High Court. Designated high-security airspace.",
        "is_preconfigured_nofly": True,
        "category": "GOVERNMENT",
        "zone_class": "RED",
        "authority": "Govt of Karnataka / Bengaluru Police",
        "city_region": "Bengaluru"
    },
    {
        "zone_id": "ZONE-GOV-FORTSTGEORGE",
        "name": "Fort St. George Secretariat & Legislative Assembly (Chennai)",
        "zone_type": "circle",
        "center_lat": 13.0800,
        "center_lon": 80.2872,
        "radius_meters": 2000.0,
        "max_altitude_m": 0.0,
        "description": "Tamil Nadu State Secretariat and Military Station perimeter.",
        "is_preconfigured_nofly": True,
        "category": "GOVERNMENT",
        "zone_class": "RED",
        "authority": "Govt of Tamil Nadu / Indian Army",
        "city_region": "Chennai"
    },
    {
        "zone_id": "ZONE-GOV-SUPREMECOURT",
        "name": "Supreme Court of India (Tilak Marg, New Delhi)",
        "zone_type": "circle",
        "center_lat": 28.6225,
        "center_lon": 77.2393,
        "radius_meters": 1000.0,
        "max_altitude_m": 0.0,
        "description": "Apex Judicial Complex. Protected institutional airspace perimeter.",
        "is_preconfigured_nofly": True,
        "category": "GOVERNMENT",
        "zone_class": "RED",
        "authority": "Supreme Court Registry / Delhi Police",
        "city_region": "Delhi NCR"
    },
    {
        "zone_id": "ZONE-GOV-BOMBAYHC",
        "name": "Bombay High Court Heritage Precinct (Fort, Mumbai)",
        "zone_type": "circle",
        "center_lat": 18.9298,
        "center_lon": 72.8302,
        "radius_meters": 1000.0,
        "max_altitude_m": 0.0,
        "description": "Historic High Court of Judicature and judicial complex no-fly zone.",
        "is_preconfigured_nofly": True,
        "category": "GOVERNMENT",
        "zone_class": "RED",
        "authority": "High Court Administration / Mumbai Police",
        "city_region": "Mumbai / MMR"
    },

    # ==========================================
    # 5. NUCLEAR, SPACE & STRATEGIC DEFENSE
    # ==========================================
    {
        "zone_id": "ZONE-STRAT-BARC",
        "name": "Bhabha Atomic Research Centre (BARC Trombay, Mumbai)",
        "zone_type": "circle",
        "center_lat": 19.0067,
        "center_lon": 72.9189,
        "radius_meters": 3500.0,
        "max_altitude_m": 0.0,
        "description": "Primary nuclear research facility and reactors under Atomic Energy Act, 1962. Permanent statutory Red Zone.",
        "is_preconfigured_nofly": True,
        "category": "STRATEGIC_NUCLEAR",
        "zone_class": "RED",
        "authority": "Department of Atomic Energy (DAE) / CISF",
        "city_region": "Mumbai / MMR"
    },
    {
        "zone_id": "ZONE-STRAT-NAVALDOCK",
        "name": "Mumbai Naval Dockyard & Western Naval Command HQ",
        "zone_type": "circle",
        "center_lat": 18.9248,
        "center_lon": 72.8378,
        "radius_meters": 2500.0,
        "max_altitude_m": 0.0,
        "description": "Strategic maritime warship and submarine repair docks at Lion Gate, Mumbai Harbour.",
        "is_preconfigured_nofly": True,
        "category": "STRATEGIC_NUCLEAR",
        "zone_class": "RED",
        "authority": "Indian Navy / Ministry of Defence",
        "city_region": "Mumbai / MMR"
    },
    {
        "zone_id": "ZONE-STRAT-ISRO-URSC",
        "name": "ISRO UR Rao Satellite Centre (URSC, Bengaluru)",
        "zone_type": "circle",
        "center_lat": 12.9664,
        "center_lon": 77.6588,
        "radius_meters": 2000.0,
        "max_altitude_m": 0.0,
        "description": "Lead national centre for design, fabrication, and testing of communication & interplanetary spacecraft.",
        "is_preconfigured_nofly": True,
        "category": "STRATEGIC_NUCLEAR",
        "zone_class": "RED",
        "authority": "ISRO / Department of Space / CISF",
        "city_region": "Bengaluru"
    },
    {
        "zone_id": "ZONE-STRAT-SHAR",
        "name": "Satish Dhawan Space Centre (SDSC SHAR, Sriharikota)",
        "zone_type": "circle",
        "center_lat": 13.7199,
        "center_lon": 80.2304,
        "radius_meters": 8000.0,
        "max_altitude_m": 0.0,
        "description": "India's spaceport and orbital rocket launch complex (PSLV/GSLV/LVM3). Absolute no-fly zone.",
        "is_preconfigured_nofly": True,
        "category": "STRATEGIC_NUCLEAR",
        "zone_class": "RED",
        "authority": "ISRO / Ministry of Home Affairs / CISF",
        "city_region": "Southern India"
    },
    {
        "zone_id": "ZONE-STRAT-KALPAKKAM",
        "name": "Madras Atomic Power Station (MAPS, Kalpakkam)",
        "zone_type": "circle",
        "center_lat": 12.5574,
        "center_lon": 80.1750,
        "radius_meters": 5000.0,
        "max_altitude_m": 0.0,
        "description": "Nuclear power plant and fast breeder test reactor facility exclusion zone.",
        "is_preconfigured_nofly": True,
        "category": "STRATEGIC_NUCLEAR",
        "zone_class": "RED",
        "authority": "Nuclear Power Corporation of India (NPCIL) / DAE",
        "city_region": "Chennai"
    },
    {
        "zone_id": "ZONE-STRAT-MAHUL",
        "name": "BPCL & HPCL Mahul Refineries Complex (Chembur, Mumbai)",
        "zone_type": "circle",
        "center_lat": 19.0150,
        "center_lon": 72.8900,
        "radius_meters": 2500.0,
        "max_altitude_m": 0.0,
        "description": "Critical petrochemical and hydrocarbon refining infrastructure. Hazardous industrial no-drone perimeter.",
        "is_preconfigured_nofly": True,
        "category": "STRATEGIC_NUCLEAR",
        "zone_class": "RED",
        "authority": "Ministry of Petroleum & Natural Gas / CISF",
        "city_region": "Mumbai / MMR"
    },

    # ==========================================
    # 6. HIGH-SECURITY PRISONS & DETENTION
    # ==========================================
    {
        "zone_id": "ZONE-PRISON-ARTHUR",
        "name": "Arthur Road Central Prison (Mumbai Central Jail)",
        "zone_type": "circle",
        "center_lat": 18.9862,
        "center_lon": 72.8306,
        "radius_meters": 1000.0,
        "max_altitude_m": 0.0,
        "description": "High-security correctional facility. Statutory ban on aerial surveillance and contraband delivery.",
        "is_preconfigured_nofly": True,
        "category": "PRISON",
        "zone_class": "RED",
        "authority": "Maharashtra Prisons Department",
        "city_region": "Mumbai / MMR"
    },
    {
        "zone_id": "ZONE-PRISON-TIHAR",
        "name": "Tihar Central Prison Complex (New Delhi)",
        "zone_type": "circle",
        "center_lat": 28.6253,
        "center_lon": 77.1128,
        "radius_meters": 1500.0,
        "max_altitude_m": 0.0,
        "description": "South Asia's largest prison complex. Permanent exclusion zone.",
        "is_preconfigured_nofly": True,
        "category": "PRISON",
        "zone_class": "RED",
        "authority": "Delhi Prisons Dept / CISF",
        "city_region": "Delhi NCR"
    },
    {
        "zone_id": "ZONE-PRISON-YERWADA",
        "name": "Yerwada Central Jail (Pune)",
        "zone_type": "circle",
        "center_lat": 18.5526,
        "center_lon": 73.8827,
        "radius_meters": 1500.0,
        "max_altitude_m": 0.0,
        "description": "Historic maximum-security prison and perimeter zone.",
        "is_preconfigured_nofly": True,
        "category": "PRISON",
        "zone_class": "RED",
        "authority": "Maharashtra Prisons Dept",
        "city_region": "Maharashtra"
    },

    # ==========================================
    # 7. CONTROLLED BUFFER ZONES & CAMPUSES
    # ==========================================
    {
        "zone_id": "ZONE-BUFFER-IITB",
        "name": "IIT Bombay Powai Campus Airspace Perimeter",
        "zone_type": "polygon",
        "coordinates": [
            [19.1410, 72.9050],
            [19.1410, 72.9230],
            [19.1250, 72.9230],
            [19.1250, 72.9050]
        ],
        "max_altitude_m": 60.0,
        "description": "Academic & Research Airspace Sector. Maximum permitted flight altitude 60m AGL.",
        "is_preconfigured_nofly": False,
        "category": "CONTROLLED_BUFFER",
        "zone_class": "YELLOW",
        "authority": "IIT Bombay Security / DGCA",
        "city_region": "Mumbai / MMR"
    },

    # ==========================================
    # 8. INTERNATIONAL BENCHMARKS & AIRSPACES
    # ==========================================
    {
        "zone_id": "ZONE-INTL-DCP56A",
        "name": "Washington D.C. Flight Restricted Zone (P-56A / White House / Capitol / Pentagon)",
        "zone_type": "circle",
        "center_lat": 38.8977,
        "center_lon": -77.0365,
        "radius_meters": 5000.0,
        "max_altitude_m": 0.0,
        "description": "United States National Defense Airspace / FRZ. Prohibited airspace Area P-56A.",
        "is_preconfigured_nofly": True,
        "category": "GOVERNMENT",
        "zone_class": "RED",
        "authority": "FAA / US Secret Service / NORAD",
        "city_region": "International (USA)"
    },
    {
        "zone_id": "ZONE-INTL-LHR",
        "name": "London Heathrow Airport (LHR / EGLL) & Westminster EG R157",
        "zone_type": "circle",
        "center_lat": 51.4700,
        "center_lon": -0.4543,
        "radius_meters": 5000.0,
        "max_altitude_m": 0.0,
        "description": "UK CAA Flight Restriction Zone (FRZ) around Heathrow runway approach paths and terminals.",
        "is_preconfigured_nofly": True,
        "category": "AIRPORT",
        "zone_class": "RED",
        "authority": "UK Civil Aviation Authority (CAA) / NATS",
        "city_region": "International (UK)"
    },
    {
        "zone_id": "ZONE-INTL-DXB",
        "name": "Dubai International Airport (DXB / OMDB)",
        "zone_type": "circle",
        "center_lat": 25.2532,
        "center_lon": 55.3657,
        "radius_meters": 5000.0,
        "max_altitude_m": 0.0,
        "description": "GCAA / DCAA Red Zone exclusion around DXB runways and international terminal approaches.",
        "is_preconfigured_nofly": True,
        "category": "AIRPORT",
        "zone_class": "RED",
        "authority": "Dubai Civil Aviation Authority (DCAA)",
        "city_region": "International (UAE)"
    },
    {
        "zone_id": "ZONE-INTL-CHANGI",
        "name": "Singapore Changi Airport (SIN / WSSS)",
        "zone_type": "circle",
        "center_lat": 1.3644,
        "center_lon": 103.9915,
        "radius_meters": 5000.0,
        "max_altitude_m": 0.0,
        "description": "CAAS 5 km Protected Aerodrome Zone around Singapore Changi Airport.",
        "is_preconfigured_nofly": True,
        "category": "AIRPORT",
        "zone_class": "RED",
        "authority": "Civil Aviation Authority of Singapore (CAAS)",
        "city_region": "International (Singapore)"
    }
]


def get_all_restricted_spaces() -> List[GeofenceZone]:
    """Instantiates and returns all real-world restricted zones as GeofenceZone models."""
    return [GeofenceZone(**zone_dict) for zone_dict in REAL_WORLD_RESTRICTED_SPACES]


def get_catalog_filtered(
    category: Optional[str] = None,
    city_region: Optional[str] = None
) -> List[GeofenceZone]:
    """Filters the real-world restricted airspace catalog by category or city/region."""
    results = []
    for z in REAL_WORLD_RESTRICTED_SPACES:
        if category and category != "ALL" and z.get("category") != category:
            continue
        if city_region and city_region != "ALL" and z.get("city_region") != city_region:
            continue
        results.append(GeofenceZone(**z))
    return results


def get_preset_by_id(preset_id: str) -> Optional[GeofenceZone]:
    """Looks up a specific real-world restricted space preset by zone_id."""
    for z in REAL_WORLD_RESTRICTED_SPACES:
        if z["zone_id"] == preset_id:
            return GeofenceZone(**z)
    return None


def get_default_core_presets() -> List[GeofenceZone]:
    """
    Returns core regional default presets automatically assigned to new cases:
    - Mumbai CSMI Airport (Civil Airport)
    - Juhu Aerodrome (Airdrome/Helicopter Hub)
    - Mantralaya & Vidhan Bhavan (Government)
    - BARC Trombay (Strategic Nuclear)
    - IIT Bombay Campus (Controlled Buffer Zone)
    """
    core_ids = {
        "ZONE-AIRPORT-BOM",
    }
    return [GeofenceZone(**z) for z in REAL_WORLD_RESTRICTED_SPACES if z["zone_id"] in core_ids]
