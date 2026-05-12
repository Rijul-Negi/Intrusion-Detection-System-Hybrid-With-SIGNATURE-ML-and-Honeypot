import pandas as pd
import os

INPUT  = "NF-UNSW-NB15-v3.csv"
OUTPUT = "NF-UNSW-NB15-v4-clean.csv"

CHUNKSIZE = 500_000
EPS = 1e-6
first = True

print("Reading:", os.path.abspath(INPUT))
print("Writing:", os.path.abspath(OUTPUT))

DROP_COLS = [
    "IPV4_SRC_ADDR",
    "IPV4_DST_ADDR",
    "L4_SRC_PORT",
    "L4_DST_PORT",
    "DNS_QUERY_ID",
    "FTP_COMMAND_RET_CODE"
]

for chunk in pd.read_csv(INPUT, chunksize=CHUNKSIZE):

    chunk.drop(columns=[c for c in DROP_COLS if c in chunk.columns],
               inplace=True, errors="ignore")

    dur_sec = chunk["FLOW_DURATION_MILLISECONDS"] / 1000.0

    chunk["IN_BYTES_PER_SEC"] = chunk["IN_BYTES"] / (dur_sec + EPS)
    chunk["IN_PKTS_PER_SEC"]  = chunk["IN_PKTS"] / (dur_sec + EPS)
    chunk["OUT_IN_BYTES_RATIO"] = (chunk["OUT_BYTES"] + 1) / (chunk["IN_BYTES"] + 1)
    chunk["PKT_SIZE_AVG"] = (
        (chunk["IN_BYTES"] + chunk["OUT_BYTES"]) /
        (chunk["IN_PKTS"] + chunk["OUT_PKTS"] + 1)
    )

    chunk["Label"] = chunk["Label"].apply(
        lambda x: 0 if str(x).lower() == "benign" else 1
    )
    chunk.to_csv(
        OUTPUT,
        mode="w" if first else "a",
        index=False,
        header=first
    )

    if first:
        print("Columns:")
        print(chunk.columns.tolist())

    first = False

print("✅ Done.")