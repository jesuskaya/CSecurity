import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest
from mpl_toolkits.mplot3d import Axes3D

np.random.seed(42)

n_normal = 500
n_anomalies = 20

normal_data = {
    "duration": np.random.normal(60, 10, n_normal),
    "src_bytes": np.random.normal(300, 50, n_normal),
    "dst_bytes": np.random.normal(200, 30, n_normal),
}

anomaly_data = {
    "duration": np.random.normal(200, 50, n_anomalies),  # suspiciously long/short
    "src_bytes": np.random.normal(2000, 500, n_anomalies),
    "dst_bytes": np.random.normal(50, 10, n_anomalies),
}

df_normal = pd.DataFrame(normal_data)
df_anomaly = pd.DataFrame(anomaly_data)
df = pd.concat([df_normal, df_anomaly], ignore_index=True)

model = IsolationForest(contamination=n_anomalies / (n_normal + n_anomalies), random_state=42)
model.fit(df[['duration', 'src_bytes', 'dst_bytes']])
df['anomaly'] = model.predict(df[['duration', 'src_bytes', 'dst_bytes']])  # -1 = anomaly

anomalies = df[df['anomaly'] == -1]
print("Detected anomalies:")
print(anomalies)

fig = plt.figure(figsize=(10, 7))
ax = fig.add_subplot(111, projection='3d')

ax.scatter(df[df['anomaly'] == 1]['duration'],
           df[df['anomaly'] == 1]['src_bytes'],
           df[df['anomaly'] == 1]['dst_bytes'],
           c='green', label='normal', s=30)

ax.scatter(df[df['anomaly'] == -1]['duration'],
           df[df['anomaly'] == -1]['src_bytes'],
           df[df['anomaly'] == -1]['dst_bytes'],
           c='red', label='anomaly', s=50, marker='x')

ax.set_xlabel("Duration (sec)")
ax.set_ylabel("Source bytes")
ax.set_zlabel("Destination bytes")
ax.set_title("Network Traffic Anomaly Detection (3D)")
ax.legend()
plt.tight_layout()
plt.show()
