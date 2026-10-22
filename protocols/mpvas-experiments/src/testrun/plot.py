import os
from pathlib import Path
from typing import Union

import matplotlib.pyplot as plt  # type: ignore
import pandas as pd

out_path = Path.cwd() / "../out"  # Must be run from `src/`!
data_path = out_path / "data"
fig_path = out_path / "figs"


def get_df(variant: str) -> Union[pd.DataFrame, None]:
    """
    Reads the experiment outputs for mPVAS [variant] and returns it as a dataframe, with times converted to seconds, or
    returns `None` if the required file could not be found.

    The `user_times` column still uses nanoseconds, since it is not used by this script.
    """

    file = data_path / f"data-mpvas-{variant}.csv"

    if os.path.isfile(file):
        df = pd.read_csv(file, header=0, sep=",", lineterminator="\n")

        for col in ["deal_time", "user_time", "aggr_time", "veri_time", "dropout_user_time"]:
            df[col] = df[col].astype(float) / 1e9

        return df
    else:
        return None


def make_mpvas_plot(df: pd.DataFrame, y_col: str, title: str) -> None:
    ks = sorted(set(df["malicious_ratio"]))

    plt.figure(0)

    line_sizes = {}
    for k in reversed(ks):
        points = df.loc[df["malicious_ratio"] == k].filter(items=["users_num", y_col]).groupby(["users_num"], sort=True)

        point_sizes = points.size().unique()
        if point_sizes.size != 1:
            raise ValueError(
                f"Not all points in figure '{title}' at k = {k} have the same sample size. "
                f"Found the following sample sizes: {points.size().to_dict()}."
            )
        line_sizes[k] = point_sizes[0]

        plt.plot("users_num", y_col, data=points.mean().reset_index(), label=f"{round(k)}%")

    if len(set(line_sizes.values())) != 1:
        raise ValueError(f"Not all lines have the same sample size. Found the following sample sizes: {line_sizes}.")

    plt.legend(title="k", title_fontproperties={"weight": "bold"})
    plt.xlabel("Number of users, n")
    plt.ylabel("Time [s]")
    plt.title(title)

    plt.savefig(fig_path / f"{title}.png")
    plt.close()


if __name__ == "__main__":
    print("Creating plots from experimental results.")
    done_msg = "done."
    skip_msg = "skipped, required results file does not exist."

    data_path.mkdir(parents=True, exist_ok=True)
    fig_path.mkdir(parents=True, exist_ok=True)

    # mPVAS
    plain_df = get_df("plain")
    print("mPVAS plain:", end=" ")
    if plain_df is None:
        print(skip_msg)
    else:
        make_mpvas_plot(plain_df, "user_time", "mPVAS, user time")
        make_mpvas_plot(plain_df, "aggr_time", "mPVAS, aggr time")
        make_mpvas_plot(plain_df, "veri_time", "mPVAS, veri time")
        print(done_msg)

    # mPVAS+
    plus_df = get_df("plus")
    print("mPVAS+:", end=" ")
    if plus_df is None:
        print(skip_msg)
    else:
        make_mpvas_plot(plus_df, "user_time", "mPVAS+, user time")
        make_mpvas_plot(plus_df, "aggr_time", "mPVAS+, aggr time")
        print(done_msg)

    # mPVAS-IV (partial tampering)
    iv_partial_df = get_df("iv-tamper-partial")
    print("mPVAS-IV (partial):", end=" ")
    if iv_partial_df is None:
        print(skip_msg)
    else:
        data1 = iv_partial_df.loc[iv_partial_df["tampers_ratio"] == 0.1]
        data2 = iv_partial_df.loc[iv_partial_df["tampers_ratio"] == 0.5]
        data3 = iv_partial_df.loc[iv_partial_df["tampers_ratio"] == 1.0]

        make_mpvas_plot(data1, "user_time", "mPVAS-IV, partial tampers, user time")
        make_mpvas_plot(data1, "aggr_time", "mPVAS-IV, 10% partial tampers, aggr time")
        make_mpvas_plot(data2, "aggr_time", "mPVAS-IV, 50% partial tampers, aggr time")
        make_mpvas_plot(data3, "aggr_time", "mPVAS-IV, 100% partial tampers, aggr time")
        print(done_msg)

    # mPVAS-IV (final tampering)
    iv_final_df = get_df("iv-tamper-final")
    print("mPVAS-IV (final):", end=" ")
    if iv_final_df is None:
        print(skip_msg)
    else:
        make_mpvas_plot(iv_final_df, "user_time", "mPVAS-IV, final tampers, user time")
        make_mpvas_plot(iv_final_df, "aggr_time", "mPVAS-IV, final tampers, aggr time")
        print(done_msg)

    # mPVAS-UD
    ud_df = get_df("ud")
    print("mPVAS-UD:", end=" ")
    if ud_df is None:
        print(skip_msg)
    else:
        data1 = ud_df.loc[ud_df["dropouts_ratio"] == 0.1]
        data2 = ud_df.loc[ud_df["dropouts_ratio"] == 0.3]
        data3 = ud_df.loc[ud_df["dropouts_ratio"] == 0.5]

        make_mpvas_plot(data1, "dropout_user_time", "mPVAS-UD, dropped-out user time")
        make_mpvas_plot(data1, "veri_time", "mPVAS-UD, 10% dropouts, veri time")
        make_mpvas_plot(data2, "veri_time", "mPVAS-UD, 30% dropouts, veri time")
        make_mpvas_plot(data3, "veri_time", "mPVAS-UD, 50% dropouts, veri time")
        print(done_msg)

    print(f"All figures done. Figures saved to '{fig_path.resolve()}'.")
