from flask import Blueprint
from flask import render_template
from markupsafe import escape
import json
from collections import defaultdict
from typing import Dict, List
from ..database.database import db
from smartshield_files.common.smartshield_utils import utils

analysis = Blueprint(
    "analysis",
    __name__,
    static_folder="static",
    static_url_path="/analysis/static",
    template_folder="templates",
)


# ----------------------------------------
# HELPER FUNCTIONS
# ----------------------------------------
def ts_to_date(ts, seconds=False):
    if seconds:
        return utils.convert_ts_format(ts, "%Y/%m/%d %H:%M:%S.%f")
    return utils.convert_ts_format(ts, "%Y/%m/%d %H:%M:%S")


def get_all_tw_with_ts(profileid):
    tws = db.get_tws_from_profile(profileid)
    dict_tws = defaultdict(dict)

    for tw_tuple in tws:
        tw_n = tw_tuple[0]
        tw_ts = tw_tuple[1]
        tw_date = ts_to_date(tw_ts)
        dict_tws[tw_n]["tw"] = tw_n
        dict_tws[tw_n]["name"] = (
            "TW " + tw_n.split("timewindow")[1] + ":" + tw_date
        )
        dict_tws[tw_n]["blocked"] = False
    return dict_tws


def get_ip_info(ip):
    """
    Retrieve IP information from database.
    db.get_ip_info(ip) returns a dict with all available fields.
    """
    full_info = db.get_ip_info(ip) or {}
    data = {
        "geocountry": full_info.get("geocountry", "-"),
        "asnorg": full_info.get("asnorg", "-"),
        "reverse_dns": full_info.get("reverse_dns", "-"),
        "threat_intel": "-",
        "url": full_info.get("url", "-"),
        "down_file": full_info.get("down_file", "-"),
        "ref_file": full_info.get("ref_file", "-"),
        "com_file": full_info.get("com_file", "-"),
    }

    # Handle threat intelligence if present as a dict
    threat = full_info.get("threatintelligence")
    if threat and isinstance(threat, dict):
        desc = threat.get("description", "-")
        level = threat.get("threat_level", "-")
        data["threat_intel"] = [f"{desc},{level} threat level"]

    return data


# ----------------------------------------
# ROUTE FUNCTIONS
# ----------------------------------------
@analysis.route("/profiles_tws")
def set_profile_tws():
    profiles_dict = {}
    profiles = db.get_profiles()
    for profileid in profiles:
        _, profile_ip = profileid.split("_")
        profiles_dict[profile_ip] = False

    blocked_profiles = db.get_malicious_profiles()
    if blocked_profiles:
        for profile in blocked_profiles:
            blocked_ip = profile.split("_")[-1]
            profiles_dict[blocked_ip] = True

    data = [
        {"profile": ip, "blocked": blocked}
        for ip, blocked in profiles_dict.items()
    ]
    return {"data": data}


@analysis.route("/info/<ip>")
def set_ip_info(ip):
    ip_info = get_ip_info(ip)
    ip_info["ip"] = ip
    return {"data": [ip_info]}


@analysis.route("/tws/<ip>")
def set_tws(ip):
    profileid = f"profile_{ip}"
    tws = get_all_tw_with_ts(profileid)

    blocked_tws = []
    for tw_id in tws:
        if db.get_profileid_twid_alerts(profileid, tw_id):
            blocked_tws.append(tw_id)

    for tw in blocked_tws:
        tws[tw]["blocked"] = True

    data = [
        {
            "tw": tw_data["tw"],
            "name": tw_data["name"],
            "blocked": tw_data["blocked"],
        }
        for tw_data in tws.values()
    ]
    return {"data": data}


@analysis.route("/intuples/<ip>/<timewindow>")
def set_intuples(ip, timewindow):
    data = []
    profileid = f"profile_{ip}"
    intuples = db.get_intuples_from_profile_tw(profileid, timewindow)
    if intuples:
        intuples = json.loads(intuples)
        for key, value in intuples.items():
            ip_addr, port, protocol = key.split("-")
            ip_info = get_ip_info(ip_addr)
            entry = {"tuple": key, "string": value[0]}
            entry.update(ip_info)
            data.append(entry)
    return {"data": data}


@analysis.route("/outtuples/<ip>/<timewindow>")
def set_outtuples(ip, timewindow):
    data = []
    profileid = f"profile_{ip}"
    outtuples = db.get_outtuples_from_profile_tw(profileid, timewindow)
    if outtuples:
        outtuples = json.loads(outtuples)
        for key, value in outtuples.items():
            ip_addr, port, protocol = key.split("-")
            ip_info = get_ip_info(ip_addr)
            entry = {"tuple": key, "string": value[0]}
            entry.update(ip_info)
            data.append(entry)
    return {"data": data}


@analysis.route("/timeline_flows/<ip>/<timewindow>")
def set_timeline_flows(ip, timewindow):
    data = []
    profileid = f"profile_{ip}"
    flows = db.get_all_flows_in_profileid_twid(profileid, timewindow)
    if flows:
        for key, value in flows.items():
            value = json.loads(value)
            value["ts"] = ts_to_date(value["ts"], seconds=True)
            value["dur"] = f"{float(value['dur']):.5f}"
            data.append(value)
    return {"data": data}


@analysis.route("/timeline/<ip>/<timewindow>")
def set_timeline(ip, timewindow):
    data = []
    profileid = f"profile_{ip}"
    timeline = db.get_profiled_tw_timeline(profileid, timewindow)
    if timeline:
        for flow in timeline:
            flow = json.loads(flow)
            # Use .get() to avoid KeyError
            if flow.get("dport_name") == "IGMP":
                for field in ["dns_resolution", "dport/proto", "state", "sent", "recv", "tot", "warning", "critical"]:
                    flow[field] = "????"
            if flow.get("preposition") == "from":
                flow["daddr"] = flow.get("saddr", "")
            data.append(flow)
    return {"data": data}


@analysis.route("/alerts/<ip>/<timewindow>")
def set_alerts(ip, timewindow):
    """
    Return a single aggregated alert row for the selected IP and timewindow,
    showing evidence counts per threat level and the SIMPLE accumulated threat level.
    Accumulated = info_count*0 + low_count*0.2 + medium_count*0.5 + high_count*0.8 + critical_count*1.0
    """
    profile = f"profile_{ip}"
    data = []

    # Check if there are any alerts for this profile/timewindow
    alerts = db.get_profileid_twid_alerts(profile, timewindow)
    if alerts:
        # Get all evidence for this timewindow
        evidence_dict = db.get_twid_evidence(profile, timewindow)
        if evidence_dict:
            # Initialize counters
            info_count = low_count = medium_count = high_count = critical_count = 0
            for ev_id, ev_json in evidence_dict.items():
                try:
                    ev_data = json.loads(ev_json)
                    threat_level = ev_data.get("threat_level", "").lower()
                    if threat_level == "info":
                        info_count += 1
                    elif threat_level == "low":
                        low_count += 1
                    elif threat_level == "medium":
                        medium_count += 1
                    elif threat_level == "high":
                        high_count += 1
                    elif threat_level == "critical":
                        critical_count += 1
                except (json.JSONDecodeError, KeyError):
                    continue

            # Compute SIMPLE accumulated threat level WITHOUT confidence
            simple_accumulated = (
                info_count * 0.0 +
                low_count * 0.2 +
                medium_count * 0.5 +
                high_count * 0.8 +
                critical_count * 1.0
            )

            # Get timewindow display name (includes date)
            tws = get_all_tw_with_ts(profile)
            tw_name = tws.get(timewindow, {}).get("name", timewindow)

            # Build the single row with detailed columns
            data.append({
                "alert": escape(tw_name),                     # timewindow name as the alert identifier
                "alert_id": "aggregated",                     # placeholder
                "profileid": escape(ip),
                "timewindow": escape(tw_name),
                # Evidence counts per threat level
                "info_count": info_count,
                "low_count": low_count,
                "medium_count": medium_count,
                "high_count": high_count,
                "critical_count": critical_count,
                # Simple accumulated value
                "accumulated_threat_level": round(simple_accumulated, 2),
            })

    return {"data": data}


@analysis.route("/evidence/<ip>/<timewindow>/<alert_id>")
def set_evidence(ip, timewindow, alert_id: str):
    data = []
    profileid = f"profile_{ip}"
    evidence_ids = db.get_evidence_causing_alert(profileid, timewindow, alert_id)
    if evidence_ids:
        for evidence_id in evidence_ids:
            evidence = db.get_evidence_by_id(profileid, timewindow, evidence_id)
            data.append(evidence)
    return {"data": data}


@analysis.route("/evidence/<ip>/<timewindow>/")
def set_evidence_general(ip: str, timewindow: str):
    data = []
    profile = f"profile_{ip}"
    evidence = db.get_twid_evidence(profile, timewindow)
    if evidence:
        for evidence_details in evidence.values():
            data.append(json.loads(evidence_details))
    return {"data": data}


@analysis.route("/")
def index():
    return render_template("analysis.html", title="smartshield")
