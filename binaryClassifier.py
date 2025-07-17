import pandas as pd
import numpy as np
import pickle
import tensorflow as tf
import matplotlib.pyplot as plt
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import confusion_matrix, classification_report
import seaborn as sns

binDatasetPaths = r"D:\DNNIDPS2\binary_filtered_dataset.csv"
binaryModel = r"D:\DNNIDPS2\binary_classifier"    #SavedModel
binScalerPath = r"D:\DNNIDPS2\binary_scaler.pkl"

# preprocessing Function for the Binary Dataset
def binaryPreprocess(df):
    df = pd.get_dummies(df, columns=["Protocol Type"])
    columnsExpectedd = [
        "Header_Length", "Protocol Type_ARP", "Protocol Type_ICMP", "Protocol Type_MQTT", "Protocol Type_TCP",
        "Protocol Type_UDP", "Protocol Type_Unknown", "fin_flag_number", "syn_flag_number", "rst_flag_number",
        "psh_flag_number", "ack_flag_number", "ece_flag_number", "cwr_flag_number", "PacketLength"
    ]
    X = df.reindex(columns=columnsExpectedd, fill_value=0)
    y = df["Binary_Label"].apply(lambda x: 0 if str(x).strip().lower() == "benign" else 1).values
    return X, y

#train the binary classifier
def main():
    print("Loading binary dataset from:", binDatasetPaths)
    df = pd.read_csv(binDatasetPaths)
    X, y = binaryPreprocess(df)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    input_dim = X_train_scaled.shape[1]

    model = Sequential([
        Dense(64, activation='relu', input_dim=input_dim),
        Dropout(0.3),
        Dense(32, activation='relu'),
        Dropout(0.3),
        Dense(1, activation='sigmoid')
    ])

    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
    model.summary()

    print("Starting training of binary classifier...")
    history = model.fit(X_train_scaled, y_train, epochs=20, batch_size=256, validation_split=0.1, verbose=1)

    loss, acc = model.evaluate(X_test_scaled, y_test, verbose=1)
    print("Binary Classifier Accuracy: {:.2f}%".format(acc * 100))

    model.save(binaryModel)
    with open(binScalerPath, "wb") as f:
        pickle.dump(scaler, f)

    # plot accuracy into visual
    plt.figure(figsize=(10, 6))
    plt.plot(history.history['accuracy'], label='Training Accuracy')
    plt.plot(history.history['val_accuracy'], label='Validation Accuracy')
    plt.title('Training and Validation Accuracy')
    plt.xlabel('Epochs')
    plt.ylabel('Accuracy')
    plt.legend()
    plt.grid(True)
    plt.show()

    #confusion Matrix
    y_pred = (model.predict(X_test_scaled) > 0.5).astype(int)
    cm = confusion_matrix(y_test, y_pred)

    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=['Benign', 'Malicious'], yticklabels=['Benign', 'Malicious'])
    plt.title('Confusion Matrix')
    plt.xlabel('Predicted Label')
    plt.ylabel('True Label')
    plt.show()

    #classification Report
    print("Classification Report:")
    print(classification_report(y_test, y_pred, target_names=['Benign', 'Malicious']))

if __name__ == "__main__":
    main()
