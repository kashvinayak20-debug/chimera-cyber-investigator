"""Matplotlib figures used by the Timeline and Graph pages (Clean modern styling)."""
from __future__ import annotations

import matplotlib
matplotlib.use("Agg")
import matplotlib.dates as mdates  # noqa: E402
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402
from matplotlib.lines import Line2D  # noqa: E402
from matplotlib.patches import FancyArrowPatch  # noqa: E402

RISK_COLORS = {
    "benign": "#3b82f6",        # Blue
    "suspicious": "#f59e0b",    # Amber
    "high": "#ef4444",          # Red
    "missing": "#8b5cf6"        # Purple
}
CHAIN_COLOR = "#ef4444"
BG_DARK = "#0b0f19"
SURFACE_DARK = "#111827"
TEXT_COLOR = "#f9fafb"
MUTED_TEXT = "#9ca3af"
BORDER_COLOR = "#1f2937"


def timeline_figure(df: pd.DataFrame, rep: dict):
    """Chain events on a clean dark time axis; potential missing events as dashed purple markers."""
    fig, ax = plt.subplots(figsize=(12, 3.2), facecolor=BG_DARK)
    ax.set_facecolor(SURFACE_DARK)
    
    ts = df["timestamp"]
    for _, r in df.iterrows():
        color = RISK_COLORS.get(r["risk"], "#3b82f6")
        ax.scatter(r["timestamp"], 1, s=150, color=color, edgecolor="#ffffff", linewidth=1.0, zorder=4)
        ax.annotate(
            f"{r['step']}. {r['event_type']}\n{r['timestamp'].strftime('%H:%M:%S')}",
            (r["timestamp"], 1),
            textcoords="offset points",
            xytext=(0, 15 if r["step"] % 2 else -35),
            ha="center",
            fontsize=8,
            fontfamily="sans-serif",
            color=TEXT_COLOR,
            fontweight="500"
        )
        
    day = ts.iloc[0].strftime("%Y-%m-%d ")
    for m in rep.get("missing_events", []):
        if m.get("expected_after") and m.get("expected_before"):
            a = pd.Timestamp(day + m["expected_after"])
            b = pd.Timestamp(day + m["expected_before"])
            mid = a + (b - a) / 2
            ax.scatter(mid, 1, s=200, facecolor="none", edgecolor="#8b5cf6", linestyle="--", linewidth=1.8, zorder=5)
            ax.annotate(
                f"[Unlogged] {m['stage']}\n({m['confidence']*100:.0f}%)",
                (mid, 1),
                textcoords="offset points",
                xytext=(0, -52),
                ha="center",
                fontsize=7.5,
                fontfamily="sans-serif",
                color="#c084fc",
                fontweight="600"
            )
            
    ax.plot(ts, [1] * len(ts), color="#3b82f6", linewidth=2, alpha=0.6, zorder=2)
    ax.set_yticks([])
    ax.set_ylim(0.1, 1.9)
    pad = pd.Timedelta(minutes=3)
    ax.set_xlim(ts.iloc[0] - pad, ts.iloc[-1] + pad)
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
    ax.set_xlabel("Timeline (UTC)", color=MUTED_TEXT, fontsize=9, fontfamily="sans-serif", fontweight="500", labelpad=8)
    ax.tick_params(colors=MUTED_TEXT, labelsize=8)
    
    for s in ("top", "right", "left"):
        ax.spines[s].set_visible(False)
    ax.spines["bottom"].set_color(BORDER_COLOR)
    ax.spines["bottom"].set_linewidth(1.0)
    
    fig.tight_layout()
    return fig


def dag_figure(chain: dict, rep: dict, events_df: pd.DataFrame):
    """Clean graph preview."""
    fig, ax = plt.subplots(figsize=(10, 4), facecolor=BG_DARK)
    ax.set_facecolor(SURFACE_DARK)
    ax.text(0.5, 0.5, "Interactive PyVis Corkboard available in '3_Graph'",
            color=MUTED_TEXT, fontsize=12, ha="center", va="center", fontfamily="sans-serif")
    ax.axis("off")
    fig.tight_layout()
    return fig
