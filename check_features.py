import pandas as pd

df = pd.read_csv("live_network_flows.csv")

print("Live Flow Features:")
print(list(df.columns))

print("\nLive Flow Data:")
print(df)