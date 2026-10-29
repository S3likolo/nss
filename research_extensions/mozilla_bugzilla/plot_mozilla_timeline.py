#!/usr/bin/env python3
"""
Mozilla NSS Bugzilla Visualization
==================================

Generates paper-quality plots illustrating:
1. Historical Trust Store Actions per Year (2000-2026): Additions, Removals, Distrusts, Modifications
2. Policy-to-Deployment Lead Time Distribution (Bug Filing to Git Commit)
3. The Multi-Stage Enforcement Lag for Major Incidents (WoSign, Symantec, SHA-1, Entrust)

Outputs:
  - research_extensions/mozilla_bugzilla/mozilla_trust_actions.png
"""

from __future__ import annotations

import logging
from pathlib import Path

import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import numpy as np
import pandas as pd
import seaborn as sns

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("plot_mozilla")

SCRIPT_DIR = Path(__file__).resolve().parent
DATA_PARQUET = SCRIPT_DIR / "mozilla_bug_metadata.parquet"
OUTPUT_PNG = SCRIPT_DIR / "mozilla_trust_actions.png"


def generate_visualizations() -> None:
    df = pd.read_parquet(DATA_PARQUET)

    # Style configuration
    plt.style.use("seaborn-v0_8-whitegrid" if "seaborn-v0_8-whitegrid" in plt.style.available else "default")
    plt.rcParams["font.sans-serif"] = ["DejaVu Sans", "Arial", "Helvetica"]
    plt.rcParams["axes.edgecolor"] = "#cccccc"
    plt.rcParams["axes.linewidth"] = 0.8

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(13, 10), gridspec_kw={"height_ratios": [1.2, 1]})

    # -----------------------------------------------------------------------
    # Plot 1: Annual Trust Store Actions by Type
    # -----------------------------------------------------------------------
    df["year"] = pd.to_datetime(df["commit_date_iso"]).dt.year
    df_actions = df[df["action_type"].isin(["ADD", "REMOVAL", "DISTRUST", "MODIFY"])]

    # Deduplicate by commit_hash and action_type so multi-bug commits don't artificially multiply
    df_unique_actions = df_actions.drop_duplicates(subset=["commit_hash", "action_type"])
    action_by_year = (
        df_unique_actions.groupby(["year", "action_type"])
        .size()
        .unstack(fill_value=0)
    )

    # Reindex to ensure continuous year range from 2001 to 2026
    all_years = range(2001, 2027)
    action_by_year = action_by_year.reindex(all_years, fill_value=0)

    color_map = {
        "ADD": "#2ecc71",       # Emerald green
        "REMOVAL": "#e74c3c",   # Alizarin red
        "DISTRUST": "#8e44ad",  # Amethyst purple
        "MODIFY": "#f39c12",    # Sunflower orange
    }

    bottom = np.zeros(len(action_by_year))
    for action in ["ADD", "MODIFY", "REMOVAL", "DISTRUST"]:
        if action in action_by_year.columns:
            vals = action_by_year[action].values
            ax1.bar(
                action_by_year.index,
                vals,
                bottom=bottom,
                label=f"{action} ({action_by_year[action].sum()} total)",
                color=color_map.get(action, "#95a5a6"),
                edgecolor="white",
                linewidth=0.5,
                width=0.75,
            )
            bottom += vals

    ax1.set_title(
        "Mozilla NSS Trust Store Actions in certdata.txt (2001–2026)\n"
        "Categorized via Bugzilla Ticket Metadata & Commit Messages",
        fontsize=14,
        fontweight="bold",
        pad=12,
    )
    ax1.set_xlabel("Year of Commit", fontsize=11, labelpad=8)
    ax1.set_ylabel("Number of Actions", fontsize=11, labelpad=8)
    ax1.set_xticks(list(range(2002, 2027, 2)))
    ax1.yaxis.set_major_locator(ticker.MaxNLocator(integer=True))
    ax1.legend(loc="upper left", frameon=True, facecolor="white", framealpha=0.9, fontsize=10)

    # Annotate key historical events
    ax1.annotate(
        "WoSign / StartCom\nPurge (Oct 2017)",
        xy=(2017, 18),
        xytext=(2014.5, 23),
        arrowprops=dict(facecolor="#2c3e50", shrink=0.08, width=1.5, headwidth=6),
        fontsize=9,
        fontweight="bold",
        bbox=dict(boxstyle="round,pad=0.3", fc="#ecf0f1", ec="#bdc3c7"),
    )

    ax1.annotate(
        "Symantec Distrust-After\n& Prune (2020)",
        xy=(2020, 14),
        xytext=(2018.5, 19),
        arrowprops=dict(facecolor="#2c3e50", shrink=0.08, width=1.5, headwidth=6),
        fontsize=9,
        fontweight="bold",
        bbox=dict(boxstyle="round,pad=0.3", fc="#ecf0f1", ec="#bdc3c7"),
    )

    ax1.annotate(
        "Entrust Distrust-After\n(2024)",
        xy=(2024, 7),
        xytext=(2022.5, 12),
        arrowprops=dict(facecolor="#2c3e50", shrink=0.08, width=1.5, headwidth=6),
        fontsize=9,
        fontweight="bold",
        bbox=dict(boxstyle="round,pad=0.3", fc="#ecf0f1", ec="#bdc3c7"),
    )

    # -----------------------------------------------------------------------
    # Plot 2: Policy-to-Deployment Lead Time Distribution
    # -----------------------------------------------------------------------
    lead_df = df.dropna(subset=["lead_time_days"]).copy()
    # Filter reasonable bounds for display (0 to 365 days; long multi-year audits noted in text)
    bounded_lead = lead_df[lead_df["lead_time_days"].between(0, 365)]

    palette = [color_map[a] for a in ["ADD", "REMOVAL", "MODIFY", "DISTRUST"]]
    sns.boxplot(
        data=bounded_lead,
        x="action_type",
        y="lead_time_days",
        order=["ADD", "MODIFY", "REMOVAL", "DISTRUST"],
        palette=palette,
        ax=ax2,
        width=0.45,
        fliersize=3,
    )

    # Overlay jittered strip points
    sns.stripplot(
        data=bounded_lead,
        x="action_type",
        y="lead_time_days",
        order=["ADD", "MODIFY", "REMOVAL", "DISTRUST"],
        color="#2c3e50",
        alpha=0.35,
        size=4,
        jitter=0.2,
        ax=ax2,
    )

    ax2.set_title(
        "Policy-to-Deployment Lag by Action Type (Days from Bug Filing to certdata.txt Commit)",
        fontsize=13,
        fontweight="bold",
        pad=10,
    )
    ax2.set_xlabel("Trust Store Action Type", fontsize=11, labelpad=8)
    ax2.set_ylabel("Lead Time (Days)", fontsize=11, labelpad=8)
    ax2.set_ylim(-10, 380)

    # Add median labels
    medians = bounded_lead.groupby("action_type")["lead_time_days"].median()
    for idx, act in enumerate(["ADD", "MODIFY", "REMOVAL", "DISTRUST"]):
        if act in medians:
            med_val = medians[act]
            ax2.text(
                idx,
                med_val + 12,
                f"Median:\n{med_val:.0f} d",
                horizontalalignment="center",
                fontsize=9,
                fontweight="bold",
                color="#1a252f",
                bbox=dict(boxstyle="round,pad=0.2", fc="#ffffff", ec="#bdc3c7", alpha=0.9),
            )

    plt.tight_layout()
    plt.savefig(OUTPUT_PNG, dpi=300)
    plt.close()
    logger.info("Saved visualization to %s", OUTPUT_PNG)


if __name__ == "__main__":
    generate_visualizations()
