import pyshark
import tensorflow as tf
import pickle
import numpy as np
import pandas as pd
import subprocess

# binary classifier files
binModelPath = r"D:\DNNIDPS2\binary_classifier"
binScalerPath = r"D:\DNNIDPS2\binary_scaler.pkl"

# multiclass classifier files
multiModelPath = r"D:\DNNIDPS2\multiclass_classifier"
multiScalerPath = r"D:\DNNIDPS2\multiclass_scaler.pkl"
labelEncPath = r"D:\DNNIDPS2\label_encoder.pkl"

print("Loading binary classifier and scaler:")
binModel = tf.keras.models.load_model(binModelPath)
with open(binScalerPath, "rb") as f:
    binScaler = pickle.load(f)

print("Loading multiclass classifier, scaler, and label encoder:")
multiModel = tf.keras.models.load_model(multiModelPath)
with open(multiScalerPath, "rb") as f:
    multiScaler = pickle.load(f)
with open(labelEncPath, "rb") as f:
    labelEnc = pickle.load(f)

malThreshold = 0.9

# The order of features as the scaler was trained on
ordered_feature_names = [
    "Header_Length", 
    "Protocol Type_ARP", "Protocol Type_ICMP", "Protocol Type_MQTT",
    "Protocol Type_TCP", "Protocol Type_UDP", "Protocol Type_Unknown",
    "fin_flag_number", "syn_flag_number", "rst_flag_number", "psh_flag_number",
    "ack_flag_number", "ece_flag_number", "cwr_flag_number", "PacketLength"
]

def extractFeatures(packet):
    features = []
    
    try:
        header_length = int(packet.ip.hdr_len)
    except AttributeError:
        header_length = 0
    features.append(header_length)
    
    protocol = packet.highest_layer.upper() if hasattr(packet, 'highest_layer') else "UNKNOWN"
    protocol_onehot = {
        "TCP": [0, 0, 0, 1, 0, 0],
        "UDP": [0, 0, 0, 0, 1, 0],
        "ICMP": [0, 1, 0, 0, 0, 0],
        "MQTT": [0, 0, 1, 0, 0, 0],
        "ARP": [1, 0, 0, 0, 0, 0]
    }.get(protocol, [0, 0, 0, 0, 0, 1])
    
    features.extend(protocol_onehot)
    
    tcp_flags = ["flags_fin", "flags_syn", "flags_rst", "flags_psh", "flags_ack", "flags_ece", "flags_cwr"]
    if 'TCP' in packet:
        for flag in tcp_flags:
            try:
                flag_str = getattr(packet.tcp, flag)
                flag_val = int(flag_str, 0)
            except Exception:
                flag_val = 0
            features.append(flag_val)
    else:
        features.extend([0] * len(tcp_flags))
    
    try:
        packet_length = int(packet.length)
    except AttributeError:
        packet_length = 0
    features.append(packet_length)
    
    features_df = pd.DataFrame([features], columns=ordered_feature_names)
    return features_df

def processPacket(packet):
    try:
        features_df = extractFeatures(packet)
    except Exception as e:
        print("Error extracting features from packet:", e)
        return
    
    try:
        features_bin = binScaler.transform(features_df)
    except Exception as e:
        print("Error occurred scaling features for binary classifier:", e)
        return
    
    pred_bin = binModel.predict(features_bin)
    malicious_prob = pred_bin[0][0]
    print(f"[Binary] Malicious probability: {malicious_prob:.2f}")
    
    if malicious_prob >= malThreshold:
        try:
            features_multi = multiScaler.transform(features_df)
        except Exception as e:
            print("Error scaling features for multiclass classifier:", e)
            return
        
        pred_multi = multiModel.predict(features_multi)
        attack_class_idx = np.argmax(pred_multi)
        attack_class = labelEnc.inverse_transform([attack_class_idx])[0]
        print(f"ALERT: Malicious packet detected, Classified attack: {attack_class}")
        
        src_ip = getattr(packet.ip, 'src', None)
        if src_ip:
            blockIP(src_ip)
    else:
        print("Packet classified as benign.")

def blockIP(ip_address):
    try:
        command = f'netsh advfirewall firewall add rule name="Block IP {ip_address}" protocol=TCP dir=in remoteip={ip_address} action=block'
        subprocess.run(command, shell=True)
        print(f"Blocked IP Address: {ip_address}")
    except Exception as e:
        print(f"Error blocking IP address {ip_address}: {e}")

def liveCapPyshark(interface_name):
    print(f"Starting live packet capture on interface: {interface_name}")
    capture = pyshark.LiveCapture(interface=interface_name)
    try:
        for packet in capture.sniff_continuously():
            if hasattr(packet, 'ip'):
                print(f"Processing Packet: Source IP: {packet.ip.src}, Destination IP: {packet.ip.dst}")
            else:
                print("Processing Non-IP Packet")
            processPacket(packet)
    except KeyboardInterrupt:
        print("Live capture stopped by user.")

if __name__ == "__main__":
    interfaceName = "WiFi" #this can be changed depdending on the network interface
    liveCapPyshark(interfaceName)
