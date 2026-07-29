import base64
from io import BytesIO

import matplotlib.pyplot as plt
import matplotlib.ticker as mticker

STATUS_COLORS = {"pass": "#27ae60", "fail": "#c0392b", "manual": "#d68910"}
SEV_COLORS = {"Critical": "#6c3483", "High": "#c0392b", "Medium": "#d68910", "Low": "#7d8a2e"}
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]


def _fig_to_data_uri(fig: plt.Figure) -> str:
    buf = BytesIO()
    fig.savefig(buf, format="png", dpi=120, bbox_inches="tight", facecolor="white")
    buf.seek(0)
    data = base64.b64encode(buf.read()).decode()
    plt.close(fig)
    return f"data:image/png;base64,{data}"


def donut_chart(summary: dict) -> str:
    labels = []
    sizes = []
    colors = []
    for status in ("pass", "fail", "manual"):
        count = summary.get(status, 0)
        if count > 0:
            labels.append(status.capitalize())
            sizes.append(count)
            colors.append(STATUS_COLORS[status])

    if not sizes:
        fig, ax = plt.subplots(figsize=(2.5, 2.5))
        ax.text(0.5, 0.5, "No data", ha="center", va="center", fontsize=12, color="#999")
        ax.set_xlim(0, 1)
        ax.set_ylim(0, 1)
        ax.axis("off")
        return _fig_to_data_uri(fig)

    fig, ax = plt.subplots(figsize=(2.5, 2.5))
    wedges, texts = ax.pie(
        sizes,
        labels=None,
        colors=colors,
        startangle=90,
        wedgeprops={"width": 0.38, "edgecolor": "white", "linewidth": 2},
    )
    centre_circle = plt.Circle((0, 0), 0.55, fc="white")
    ax.add_artist(centre_circle)
    total = sum(sizes)
    ax.text(0, 0, str(total), ha="center", va="center", fontsize=20, fontweight="bold", color="#2c3e50")
    ax.text(0, -0.18, "total", ha="center", va="center", fontsize=8, color="#7f8c8d")
    ax.axis("equal")
    legend_labels = [f"{l} ({s})" for l, s in zip(labels, sizes)]
    ax.legend(wedges, legend_labels, loc="center left", bbox_to_anchor=(1, 0.5), frameon=False, fontsize=8)
    return _fig_to_data_uri(fig)


def severity_bar_chart(by_severity: dict) -> str:
    labels = []
    values = []
    colors = []
    for sev in SEVERITY_ORDER:
        count = by_severity.get(sev, 0)
        if count > 0:
            labels.append(sev)
            values.append(count)
            colors.append(SEV_COLORS[sev])

    if not values:
        fig, ax = plt.subplots(figsize=(4, 1.5))
        ax.text(0.5, 0.5, "No data", ha="center", va="center", fontsize=10, color="#999")
        ax.set_xlim(0, 1)
        ax.set_ylim(0, 1)
        ax.axis("off")
        return _fig_to_data_uri(fig)

    fig, ax = plt.subplots(figsize=(4, 1.6))
    bars = ax.barh(labels, values, color=colors, height=0.55, edgecolor="white", linewidth=1)
    for bar, val in zip(bars, values):
        ax.text(
            bar.get_width() + max(values) * 0.02,
            bar.get_y() + bar.get_height() / 2,
            str(val),
            ha="left", va="center", fontsize=10, fontweight="bold", color="#333",
        )
    ax.set_xlim(0, max(values) * 1.25 if values else 1)
    ax.tick_params(axis="y", labelsize=10)
    ax.tick_params(axis="x", labelsize=8)
    ax.xaxis.set_major_locator(mticker.MaxNLocator(integer=True))
    for spine in ax.spines.values():
        spine.set_visible(False)
    ax.tick_params(left=False)
    return _fig_to_data_uri(fig)
