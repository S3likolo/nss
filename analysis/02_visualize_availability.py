#!/usr/bin/env python3
"""
Web PKI Root Store Data Availability & Timeline Visualizer
==========================================================
Generates publication-quality charts for the empirical analysis paper:
  1. Snapshot Timeline (temporal distribution and granularity across vendors)
  2. Root Store Size Over Time (corpus growth, trimming, and vendor divergence)
  3. Descriptive Data Availability Statistics (cadence, gaps, observation windows)

Usage:
  python analysis/02_visualize_availability.py
  python analysis/02_visualize_availability.py --db-path data/normalized/root_stores.duckdb
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import Dict, Any

import duckdb
import matplotlib.dates as mdates
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns

# ---------------------------------------------------------------------------
# Logging Configuration
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("analysis.visualize_availability")

# ---------------------------------------------------------------------------
# Constants & Styling Configuration
# ---------------------------------------------------------------------------
DEFAULT_DB_PATH = Path("data/normalized/root_stores.duckdb")
DEFAULT_PLOTS_DIR = Path("analysis/plots")
FALLBACK_PLOTS_DIR = Path("plots")

# Vendor Branding Colors (accessible, distinctive, scientific)
VENDOR_COLORS = {
    "mozilla": "#E66000",   # Firefox / Mozilla Orange
    "google": "#1A73E8",    # Google Chrome Blue
    "microsoft": "#00A4EF", # Windows / Microsoft Cyan
    "apple": "#4A4A4A",     # Apple Charcoal / Platinum
}

VENDOR_MARKERS = {
    "mozilla": "o",
    "google": "s",
    "microsoft": "^",
    "apple": "D",
}

VENDOR_LABELS = {
    "mozilla": "Mozilla NSS",
    "google": "Google Chrome (CRS)",
    "microsoft": "Microsoft Windows (STL)",
    "apple": "Apple macOS/iOS",
}

VENDOR_ORDER = ["apple", "google", "microsoft", "mozilla"]


def setup_plotting_theme() -> None:
    """Configures high-resolution scientific typography and plot styles."""
    sns.set_theme(style="whitegrid", palette="deep")
    plt.rcParams.update({
        "font.family": "sans-serif",
        "font.sans-serif": ["Segoe UI", "DejaVu Sans", "Helvetica", "Arial", "sans-serif"],
        "font.size": 11,
        "axes.titlesize": 13,
        "axes.titleweight": "bold",
        "axes.labelsize": 11,
        "axes.labelweight": "semibold",
        "xtick.labelsize": 10,
        "ytick.labelsize": 10,
        "legend.fontsize": 10,
        "legend.title_fontsize": 11,
        "figure.titlesize": 15,
        "figure.titleweight": "bold",
        "figure.dpi": 300,
        "savefig.dpi": 300,
        "savefig.bbox": "tight",
        "lines.linewidth": 1.8,
        "lines.markersize": 6,
        "grid.alpha": 0.5,
        "grid.linestyle": "--",
    })


# ---------------------------------------------------------------------------
# Visualizer Class
# ---------------------------------------------------------------------------
class AvailabilityVisualizer:
    """
    Connects to DuckDB, pulls temporal metrics, and renders publication charts.
    """

    def __init__(self, db_path: Path, output_dirs: list[Path]) -> None:
        self.db_path = Path(db_path)
        self.output_dirs = [Path(d) for d in output_dirs]
        for out in self.output_dirs:
            out.mkdir(parents=True, exist_ok=True)
        self.conn = duckdb.connect(str(self.db_path), read_only=True)

    def close(self) -> None:
        """Closes database connection."""
        self.conn.close()

    def _save_figure(self, fig: plt.Figure, filename: str) -> None:
        """Saves figure to all configured target directories."""
        for d in self.output_dirs:
            target = d / filename
            fig.savefig(target, dpi=300)
            logger.info("Saved plot to: %s", target.resolve())

    # -----------------------------------------------------------------------
    # Plot 1: Snapshot Timeline
    # -----------------------------------------------------------------------
    def plot_snapshot_timeline(self, filename: str = "01_snapshot_timeline.png") -> None:
        """
        Generates an Event/Timeline chart displaying the temporal distribution
        and observation density of snapshots across all four root store vendors.
        """
        logger.info("Generating Plot 1: Snapshot Timeline...")
        query = """
        SELECT DISTINCT 
            vendor,
            CAST(snapshot_date AS DATE) AS snapshot_date
        FROM unified_trust_history
        ORDER BY vendor, snapshot_date;
        """
        df = self.conn.execute(query).df()
        df["snapshot_date"] = pd.to_datetime(df["snapshot_date"])

        fig, ax = plt.subplots(figsize=(12, 5.2))

        # Y positions for each vendor
        y_positions = {v: i for i, v in enumerate(VENDOR_ORDER)}
        y_labels = [VENDOR_LABELS[v] for v in VENDOR_ORDER]

        for vendor in VENDOR_ORDER:
            v_df = df[df["vendor"] == vendor]
            if v_df.empty:
                continue

            y_pos = y_positions[vendor]
            color = VENDOR_COLORS[vendor]
            dates = v_df["snapshot_date"]

            # Draw observation window span line
            min_date, max_date = dates.min(), dates.max()
            ax.hlines(
                y=y_pos,
                xmin=min_date,
                xmax=max_date,
                color=color,
                alpha=0.4,
                linewidth=4,
                zorder=2,
            )

            # Draw individual snapshot event markers
            ax.scatter(
                dates,
                [y_pos] * len(dates),
                color=color,
                marker="|",
                s=240,
                linewidths=2.2,
                alpha=0.9,
                zorder=3,
                label=f"{VENDOR_LABELS[vendor]} (n={len(dates)})",
            )

            # Add badge on the right displaying count and span
            span_years = (max_date - min_date).days / 365.25
            span_text = f"{len(dates)} snapshots" if len(dates) == 1 else f"{len(dates)} snapshots ({span_years:.1f} yrs)"
            ax.annotate(
                span_text,
                xy=(max_date, y_pos),
                xytext=(15, 0),
                textcoords="offset points",
                va="center",
                fontsize=9.5,
                fontweight="semibold",
                color=color,
            )

        # Formatting axes
        ax.set_yticks(range(len(VENDOR_ORDER)))
        ax.set_yticklabels(y_labels, fontweight="bold")
        ax.set_xlabel("Observation Timeline (Calendar Year)", labelpad=10)
        ax.set_title(
            "Empirical Data Availability: Historical Root Store Snapshots (2010–2026)",
            pad=15,
        )

        # X-axis formatting: major yearly ticks
        ax.xaxis.set_major_locator(mdates.YearLocator(2))
        ax.xaxis.set_major_formatter(mdates.DateFormatter("%Y"))
        ax.xaxis.set_minor_locator(mdates.YearLocator(1))
        ax.set_xlim(pd.to_datetime("2009-06-01"), pd.to_datetime("2028-06-01"))

        # Annotations for historical context
        ax.axvline(pd.to_datetime("2022-04-01"), color="#777777", linestyle=":", linewidth=1, alpha=0.7)
        ax.text(
            pd.to_datetime("2022-04-01"),
            -0.45,
            "Chrome Root Store (CRS) Launch (2022)",
            fontsize=8.5,
            style="italic",
            color="#555555",
            ha="center",
        )

        ax.legend(
            loc="lower left",
            frameon=True,
            framealpha=0.9,
            facecolor="white",
            edgecolor="#cccccc",
            title="Vendor Ecosystem",
        )
        plt.tight_layout()

        self._save_figure(fig, filename)
        plt.close(fig)

    # -----------------------------------------------------------------------
    # Plot 2: Root Store Size Over Time
    # -----------------------------------------------------------------------
    def plot_root_store_size(self, filename: str = "02_root_store_size.png") -> None:
        """
        Generates a longitudinal Line Chart showing the active corpus size
        (count of distinct trusted Root CAs) over time for each vendor.
        """
        logger.info("Generating Plot 2: Root Store Size Over Time...")
        query = """
        SELECT 
            vendor,
            CAST(snapshot_date AS DATE) AS snapshot_date,
            COUNT(DISTINCT sha256_fingerprint) AS root_count
        FROM unified_trust_history
        GROUP BY vendor, snapshot_date
        ORDER BY vendor, snapshot_date;
        """
        df = self.conn.execute(query).df()
        df["snapshot_date"] = pd.to_datetime(df["snapshot_date"])

        fig, ax = plt.subplots(figsize=(12, 6.2))

        for vendor in ["microsoft", "google", "mozilla", "apple"]:
            v_df = df[df["vendor"] == vendor].sort_values("snapshot_date")
            if v_df.empty:
                continue

            color = VENDOR_COLORS[vendor]
            marker = VENDOR_MARKERS[vendor]
            label = VENDOR_LABELS[vendor]

            if len(v_df) == 1:
                # Single point (Apple) -> prominent scatter diamond
                pt = v_df.iloc[0]
                ax.scatter(
                    pt["snapshot_date"],
                    pt["root_count"],
                    color=color,
                    marker=marker,
                    s=140,
                    zorder=5,
                    label=f"{label} ({pt['root_count']} roots)",
                    edgecolor="black",
                    linewidth=1.2,
                )
                ax.annotate(
                    f"Apple Support Snapshot\n({pt['root_count']} roots)",
                    xy=(pt["snapshot_date"], pt["root_count"]),
                    xytext=(-60, 25),
                    textcoords="offset points",
                    arrowprops=dict(arrowstyle="->", color=color, lw=1.2),
                    fontsize=9,
                    fontweight="semibold",
                    color=color,
                )
            else:
                # Continuous / step lines for multi-snapshot series
                # For Microsoft, use step line to indicate discrete CTL updates
                if vendor == "microsoft":
                    ax.step(
                        v_df["snapshot_date"],
                        v_df["root_count"],
                        where="post",
                        color=color,
                        linewidth=2.2,
                        marker=marker,
                        markersize=6,
                        alpha=0.9,
                        label=f"{label} (322 → 562 roots)",
                        zorder=4,
                    )
                else:
                    ax.plot(
                        v_df["snapshot_date"],
                        v_df["root_count"],
                        color=color,
                        linewidth=2.0,
                        marker=marker,
                        markersize=5,
                        alpha=0.85,
                        label=f"{label} ({v_df['root_count'].iloc[0]} → {v_df['root_count'].iloc[-1]} roots)",
                        zorder=4,
                    )

        # Formatting
        ax.set_title("Evolution of Active Web PKI Root Store Corpus Size (2010–2026)", pad=15)
        ax.set_xlabel("Timeline", labelpad=10)
        ax.set_ylabel("Trusted Root CA Certificates (Count)", labelpad=10)
        ax.set_ylim(100, 620)

        ax.xaxis.set_major_locator(mdates.YearLocator(2))
        ax.xaxis.set_major_formatter(mdates.DateFormatter("%Y"))
        ax.xaxis.set_minor_locator(mdates.YearLocator(1))
        ax.set_xlim(pd.to_datetime("2009-06-01"), pd.to_datetime("2027-06-01"))

        # Contextual notes
        ax.annotate(
            "Microsoft: Significant expansion\n(+74.5% net growth in trusted roots)",
            xy=(pd.to_datetime("2024-01-01"), 480),
            xytext=(-180, 40),
            textcoords="offset points",
            arrowprops=dict(arrowstyle="->", color=VENDOR_COLORS["microsoft"], lw=1),
            fontsize=8.5,
            color=VENDOR_COLORS["microsoft"],
        )

        ax.annotate(
            "Mozilla: Consistent pruning\n(-11.6% net trimming)",
            xy=(pd.to_datetime("2018-01-01"), 150),
            xytext=(30, -35),
            textcoords="offset points",
            arrowprops=dict(arrowstyle="->", color=VENDOR_COLORS["mozilla"], lw=1),
            fontsize=8.5,
            color=VENDOR_COLORS["mozilla"],
        )

        ax.legend(
            loc="upper left",
            frameon=True,
            framealpha=0.95,
            facecolor="white",
            edgecolor="#cccccc",
            title="Root Store Vendor",
        )
        plt.tight_layout()

        self._save_figure(fig, filename)
        plt.close(fig)

    # -----------------------------------------------------------------------
    # Descriptive Statistics for Paper
    # -----------------------------------------------------------------------
    def print_availability_descriptive_stats(self) -> None:
        """
        Computes snapshot intervals, maximum observation gaps, and cadence metrics
        essential for the scientific methodology section.
        """
        logger.info("Computing Descriptive Data Availability Statistics...")

        gap_query = """
        WITH ordered_snapshots AS (
            SELECT 
                vendor,
                snapshot_date,
                LAG(snapshot_date) OVER (PARTITION BY vendor ORDER BY snapshot_date) AS prev_date
            FROM (
                SELECT DISTINCT vendor, snapshot_date 
                FROM unified_trust_history
            )
        ),
        gaps AS (
            SELECT 
                vendor,
                DATEDIFF('day', prev_date, snapshot_date) AS gap_days
            FROM ordered_snapshots
            WHERE prev_date IS NOT NULL
        ),
        vendor_summary AS (
            SELECT 
                vendor,
                ANY_VALUE(data_source_type) AS source_mechanism,
                COUNT(DISTINCT snapshot_date) AS snapshot_count,
                MIN(snapshot_date) AS earliest_date,
                MAX(snapshot_date) AS latest_date,
                DATEDIFF('day', MIN(snapshot_date), MAX(snapshot_date)) AS total_span_days
            FROM unified_trust_history
            GROUP BY vendor
        )
        SELECT 
            s.vendor,
            s.source_mechanism,
            s.snapshot_count,
            s.earliest_date,
            s.latest_date,
            ROUND(s.total_span_days / 365.25, 2) AS span_years,
            COALESCE(ROUND(AVG(g.gap_days), 1), 0.0) AS avg_gap_days,
            COALESCE(ROUND(MEDIAN(g.gap_days), 1), 0.0) AS median_gap_days,
            COALESCE(MAX(g.gap_days), 0) AS max_gap_days
        FROM vendor_summary s
        LEFT JOIN gaps g ON s.vendor = g.vendor
        GROUP BY s.vendor, s.source_mechanism, s.snapshot_count, s.earliest_date, s.latest_date, s.total_span_days
        ORDER BY s.vendor;
        """

        df = self.conn.execute(gap_query).df()

        print("\n" + "=" * 95)
        print("DESCRIPTIVE DATA AVAILABILITY & TEMPORAL CADENCE METRICS (FOR PAPER)")
        print("=" * 95)
        print(df.to_string(index=False))
        print("=" * 95)

        print("\nKey Analytical Insights:")
        for _, row in df.iterrows():
            v = row["vendor"].upper()
            sn = row["snapshot_count"]
            span = row["span_years"]
            max_g = row["max_gap_days"]
            avg_g = row["avg_gap_days"]
            src = row["source_mechanism"]
            if sn == 1:
                print(f"  * {v}: Single snapshot archive ({src}). No inter-snapshot cadence measurable.")
            else:
                print(
                    f"  * {v}: {sn} snapshots over {span} years ({src}). "
                    f"Avg cadence = {avg_g:.1f} days (max gap = {max_g} days)."
                )
        print("=" * 95 + "\n")


# ---------------------------------------------------------------------------
# CLI Entrypoint
# ---------------------------------------------------------------------------
def parse_arguments() -> argparse.Namespace:
    """Parses command line arguments."""
    parser = argparse.ArgumentParser(
        description="Generate publication charts and availability metrics from DuckDB."
    )
    parser.add_argument(
        "--db-path",
        type=Path,
        default=DEFAULT_DB_PATH,
        help=f"Path to DuckDB database (default: {DEFAULT_DB_PATH}).",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_PLOTS_DIR,
        help=f"Directory to save output PNG plots (default: {DEFAULT_PLOTS_DIR}).",
    )
    return parser.parse_args()


def main() -> None:
    """Main execution function."""
    args = parse_arguments()
    setup_plotting_theme()

    visualizer = AvailabilityVisualizer(
        db_path=args.db_path,
        output_dirs=[args.output_dir, FALLBACK_PLOTS_DIR],
    )

    try:
        # Step 2: Plot 1 - Snapshot Timeline
        visualizer.plot_snapshot_timeline("01_snapshot_timeline.png")

        # Step 3: Plot 2 - Root Store Size Over Time
        visualizer.plot_root_store_size("02_root_store_size.png")

        # Step 4: Descriptive Statistics Output
        visualizer.print_availability_descriptive_stats()

    except Exception as exc:
        logger.exception("Visualization pipeline failed: %s", exc)
        sys.exit(1)
    finally:
        visualizer.close()


if __name__ == "__main__":
    main()
