
import pandas as pd

df = pd.read_csv("live_network_traffic.csv")
df["Time"] = pd.to_datetime(df["Time"])

# Create bidirectional flow groups
df["Endpoint_A"] = df[["Source IP", "Destination IP"]].min(axis=1)
df["Endpoint_B"] = df[["Source IP", "Destination IP"]].max(axis=1)

df["Direction"] = [
    "forward" if src == a else "reverse"
    for src, a in zip(df["Source IP"], df["Endpoint_A"])
]

# Extract flow features
flows = df.groupby(
    ["Endpoint_A", "Endpoint_B", "Protocol"]
).agg(
    spkts=("Direction", lambda x: (x == "forward").sum()),
    dpkts=("Direction", lambda x: (x == "reverse").sum()),
    sbytes=("Packet Size", lambda x: x[df.loc[x.index, "Direction"] == "forward"].sum()),
    dbytes=("Packet Size", lambda x: x[df.loc[x.index, "Direction"] == "reverse"].sum()),
    sttl=("TTL", lambda x: x[df.loc[x.index, "Direction"] == "forward"].mean()),
    dttl=("TTL", lambda x: x[df.loc[x.index, "Direction"] == "reverse"].mean()),
    first_time=("Time", "min"),
    last_time=("Time", "max")
).reset_index()

# Calculate additional features
flows["dur"] = (
    flows["last_time"] - flows["first_time"]
).dt.total_seconds()

flows["rate"] = (
    (flows["spkts"] + flows["dpkts"]) /
    flows["dur"].replace(0, 1)
)

flows["smean"] = (
    flows["sbytes"] / flows["spkts"].replace(0, 1)
)

flows["dmean"] = (
    flows["dbytes"] / flows["dpkts"].replace(0, 1)
)

# Rename columns
flows = flows.rename(columns={
    "Endpoint_A": "Source IP",
    "Endpoint_B": "Destination IP",
    "Protocol": "proto"
})

# Save flow data
flows.to_csv("live_network_flows.csv", index=False)

print("Live Flow Feature Extraction Completed!")
print(flows)
print("\nSaved as live_network_flows.csv")


