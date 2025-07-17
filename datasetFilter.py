import pandas as pd

#Defined file paths used for saving and loading relavant material
datasetPath = r"D:\DNNIDPS2\combined_train_dataset.csv"
outputDirectory = r"D:\DNNIDPS2"
filteredDatasetPath = outputDirectory + "filtered_train_dataset.csv"
binaryDatasetPath = outputDirectory + "binary_filtered_dataset.csv"
maliciousDatasetPath = outputDirectory + "malicious_filtered_dataset.csv"

#Inference function for protocol type based on attack category, inference comes from string in Attack_Category Column
def findProtocol(row):
    category = str(row["Attack_Category"]).lower()
    if "mqtt" in category:
        return "MQTT"
    elif "arp" in category:
        return "ARP"
    elif "icmp" in category or "ping" in category:
        return "ICMP"
    elif "udp" in category:
        return "UDP"
    elif ("tcp" in category or "syn" in category or "port scan" in category or 
          "os scan" in category or "recon" in category):
        return "TCP"
    else:
        return "Unknown"

#Filter function to get contents suitable to PyShark capabilities
def filterForPyshark(df):
    neededColumns = [
        "Header_Length",
        "Protocol Type",
        "fin_flag_number",
        "syn_flag_number",
        "rst_flag_number",
        "psh_flag_number",
        "ack_flag_number",
        "ece_flag_number",
        "cwr_flag_number",
        "Tot size",  
        "Attack_Category"
    ]
    keepColumns = [col for col in neededColumns if col in df.columns]
    df_filtered = df[keepColumns].copy()

    if "Tot size" in df_filtered.columns:
        df_filtered.rename(columns={"Tot size": "PacketLength"}, inplace=True)

    df_filtered["Protocol Type"] = df_filtered.apply(findProtocol, axis=1)
    return df_filtered

#Balancing function for attack categories - limits to 50000, uses resampling for lacking classes
def datasetBalancer(df, target_samples=50000):
    balanced_dfs = []
    for label, group in df.groupby("Attack_Category"):
        if len(group) < target_samples:
            balanced_group = group.sample(n=target_samples, replace=True, random_state=42)
        elif len(group) > target_samples:
            balanced_group = group.sample(n=target_samples, random_state=42)
        else:
            balanced_group = group.copy()
        balanced_dfs.append(balanced_group)
    balanced_df = pd.concat(balanced_dfs).sample(frac=1, random_state=42).reset_index(drop=True)
    return balanced_df

def main():
    df = pd.read_csv(datasetPath)
    df_filtered = filterForPyshark(df)
    df_filtered["Binary_Label"] = df_filtered["Attack_Category"].apply(
        lambda x: "benign" if str(x).strip().lower() == "benign" else "malicious"
    )
    
    df_balanced = datasetBalancer(df_filtered, target_samples=50000)
    
    #Onehot encoding for protocol type
    df_balanced = pd.get_dummies(df_balanced, columns=["Protocol Type"])
    
    #definea the correct column order expected by the DNN model
    columnsExpected = [
        "Header_Length",
        "Protocol Type_ARP",
        "Protocol Type_ICMP",
        "Protocol Type_MQTT",
        "Protocol Type_TCP",
        "Protocol Type_UDP",
        "Protocol Type_Unknown",
        "fin_flag_number",
        "syn_flag_number",
        "rst_flag_number",
        "psh_flag_number",
        "ack_flag_number",
        "ece_flag_number",
        "cwr_flag_number",
        "PacketLength",
        "Attack_Category",
        "Binary_Label"
    ]
    
    # Reindexing the DataFrame to match the expected order of columns
    df_balanced = df_balanced.reindex(columns=columnsExpected, fill_value=0)
    
    # Balance benign and malicious samples
    benignSample = df_balanced[df_balanced["Binary_Label"] == "benign"]
    malSamples = df_balanced[df_balanced["Binary_Label"] == "malicious"]
    targetSample = min(len(benignSample), len(malSamples))

    balancedBenignDS = benignSample.sample(n=targetSample, random_state=42, replace=True)
    balancesMalDS = malSamples.sample(n=targetSample, random_state=42, replace=True)

    balacnedBinaryDS = pd.concat([balancedBenignDS, balancesMalDS]).sample(frac=1, random_state=42).reset_index(drop=True)

    #save the binary balanced dataset to earlier directory
    balacnedBinaryDS.to_csv(binaryDatasetPath, index=False)
    
    #save the filtered balanced dataset to specified path
    df_balanced.to_csv(filteredDatasetPath, index=False)

    # Save the malicious-only dataset for multiclass classification
    df_malicious = df_balanced[df_balanced["Binary_Label"] == "malicious"].copy()
    df_malicious.to_csv(maliciousDatasetPath, index=False)

    print("Datasets created successfully")
    
if __name__ == "__main__":
    main()
