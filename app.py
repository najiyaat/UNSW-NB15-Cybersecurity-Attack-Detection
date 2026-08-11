import streamlit as st
import pandas as pd
import joblib

model = joblib.load("random_forest_model.pkl")

st.set_page_config(page_title="Network Intrusion Detection System", layout="centered")

st.title("🔒 Network Intrusion Detection System")
st.write("Enter the important network features below.")

# -------- User Inputs --------

col1, col2, col3 = st.columns(3)

with col1:
    dur = st.number_input("Duration (dur)", value=0.014)

with col2:
    sbytes = st.number_input("Source Bytes (sbytes)", value=534.0)

with col3:
    dbytes = st.number_input("Destination Bytes (dbytes)", value=178.0)

col1, col2, col3 = st.columns(3)

with col1:
    rate = st.number_input("Rate", value=2650.177)

with col2:
    sttl = st.number_input("Source TTL", value=254)

with col3:
    dttl = st.number_input("Destination TTL", value=29)

col1, col2, col3 = st.columns(3)

with col1:
    sload = st.number_input("Source Load", value=577003.2)

with col2:
    tcprtt = st.number_input("TCP RTT", value=0.000551)

with col3:
    synack = st.number_input("SYN ACK", value=0.000441)

if st.button("Predict"):

    data = {
        "dur": dur,
        "proto": 111,
        "service": 0,
        "state": 3,
        "spkts": 6,
        "dpkts": 2,
        "sbytes": sbytes,
        "dbytes": dbytes,
        "rate": rate,
        "sttl": sttl,
        "dttl": dttl,
        "sload": sload,
        "dload": 2112.951,
        "sloss": 1,
        "dloss": 0,
        "sinpkt": 0.5579285,
        "dinpkt": 0.01,
        "sjit": 17.62392,
        "djit": 0,
        "swin": 255,
        "stcpb": 27888860,
        "dtcpb": 28569750,
        "dwin": 255,
        "tcprtt": tcprtt,
        "synack": synack,
        "ackdat": 0.00008,
        "smean": 65,
        "dmean": 44,
        "trans_depth": 0,
        "response_body_len": 0,
        "ct_srv_src": 5,
        "ct_state_ttl": 1,
        "ct_dst_ltm": 2,
        "ct_src_dport_ltm": 1,
        "ct_dst_sport_ltm": 1,
        "ct_dst_src_ltm": 3,
        "is_ftp_login": 0,
        "ct_ftp_cmd": 0,
        "ct_flw_http_mthd": 0,
        "ct_src_ltm": 3,
        "ct_srv_dst": 5,
        "is_sm_ips_ports": 0
    }

    df = pd.DataFrame([data])

    prediction = model.predict(df)

    if prediction[0] == 1:
        st.error("🚨 Attack Detected")
    else:
        st.success("✅ Normal Traffic")