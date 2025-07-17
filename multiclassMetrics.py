import pandas as pd
import numpy as np
import tensorflow as tf
import matplotlib.pyplot as plt
import seaborn as sns
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout, BatchNormalization, LeakyReLU
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import confusion_matrix, classification_report
from tensorflow.keras.utils import to_categorical

maliciousDataPath = r"D:\DNNIDPS2\malicious_filtered_dataset.csv"

#preprocessing function for multiclass data
def preprocess_for_multiclass(df):
    df = pd.get_dummies(df, columns=["Protocol Type"])
    expectedCols = [
        "Header_Length", "Protocol Type_ARP", "Protocol Type_ICMP", "Protocol Type_MQTT", "Protocol Type_TCP",
        "Protocol Type_UDP", "Protocol Type_Unknown", "fin_flag_number", "syn_flag_number", "rst_flag_number",
        "psh_flag_number", "ack_flag_number", "ece_flag_number", "cwr_flag_number", "PacketLength"
    ]
    X = df.reindex(columns=expectedCols, fill_value=0)
    y = df["Attack_Category"]
    return X, y

#train the multiclass classifier - DNN
def main():
    df = pd.read_csv(maliciousDataPath)
    X, y = preprocess_for_multiclass(df)

    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y)
    y_categorical = to_categorical(y_encoded)

    X_train, X_test, y_train, y_test = train_test_split(X, y_categorical, test_size=0.2, random_state=42, stratify=y_encoded)

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    input_dim = X_train_scaled.shape[1]
    num_classes = y_categorical.shape[1]

    model = Sequential([
        Dense(1024, input_dim=input_dim),
        BatchNormalization(),
        LeakyReLU(alpha=0.1),
        Dropout(0.4),

        Dense(512),
        BatchNormalization(),
        LeakyReLU(alpha=0.1),
        Dropout(0.4),

        Dense(256),
        BatchNormalization(),
        LeakyReLU(alpha=0.1),
        Dropout(0.3),

        Dense(128),
        BatchNormalization(),
        LeakyReLU(alpha=0.1),
        Dropout(0.2),

        Dense(num_classes, activation='softmax')
    ])

    model.compile(optimizer=tf.keras.optimizers.Adam(learning_rate=0.001), loss='categorical_crossentropy', metrics=['accuracy'])

    history = model.fit(X_train_scaled, y_train, epochs=30, batch_size=256, validation_split=0.1, verbose=1)

    loss, acc = model.evaluate(X_test_scaled, y_test, verbose=1)
    print(f"Multiclass Classifier Accuracy: {acc * 100:.2f}%")

    #plot accuracy
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
    y_pred = np.argmax(model.predict(X_test_scaled), axis=1)
    y_test_labels = np.argmax(y_test, axis=1)
    cm = confusion_matrix(y_test_labels, y_pred)

    plt.figure(figsize=(12, 8))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=label_encoder.classes_, yticklabels=label_encoder.classes_)
    plt.title('Confusion Matrix')
    plt.xlabel('Predicted Label')
    plt.ylabel('True Label')
    plt.show()

    #classification Report
    print("\nClassification Report:")
    print(classification_report(y_test_labels, y_pred, target_names=label_encoder.classes_))


if __name__ == "__main__":
    main()
