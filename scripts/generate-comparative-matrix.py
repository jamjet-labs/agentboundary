#!/usr/bin/env python3
"""Generate the W12 cross-vendor conformance matrix as an SVG.

Reads the verdict table below (one row per scenario, one column per
vendor) and renders a single-page SVG suitable for the comparative
report's hero figure. Run with::

    python3 scripts/generate-comparative-matrix.py

Writes to ``docs/assets/comparative-matrix.svg``.

When a scenario or vendor verdict changes, edit ``MATRIX`` here and
re-run. The SVG is a deterministic function of the table; never edit
the SVG by hand.
"""

from __future__ import annotations

from pathlib import Path

# Verdict codes
PASS = "PASS"
PART = "PART"  # PARTIAL
DOCS = "DOCS"  # DOCS-ONLY
NCOV = "----"  # NOT COVERED
NA = "N/A"

# Vendor columns, in alphabetical order so the matrix can't be read as
# a leaderboard. JamJet (the spec's reference implementation) is first;
# it passes everything by construction.
VENDORS = (
    "JamJet ref",
    "Anthropic",
    "Cloudflare",
    "LangSmith",
    "Microsoft AGT",
)

# (scenario_number, scenario_short_name, verdicts...) where verdicts
# matches the order of VENDORS above.
MATRIX: tuple[tuple[str, str, str, str, str, str, str], ...] = (
    # # name                                 JamJet  Anth  Cloud  LS    AGT
    ("01", "merge-allow", PASS, PART, PART, PART, PASS),
    ("02", "mutation-require-approval", PASS, PASS, PASS, PART, PART),
    ("03", "refund-under-limit", PASS, PART, PART, PART, PASS),
    ("04", "merge-deny", PASS, PASS, PASS, PART, PASS),
    ("05", "refund-escalate", PASS, NCOV, NCOV, PART, PASS),
    ("06", "missing-policy-block", PASS, NCOV, NCOV, NCOV, PART),
    ("07", "bad-timestamp-format", PASS, DOCS, PASS, PASS, PASS),
    ("08", "arguments-hash-mismatch", PASS, PASS, NCOV, PASS, NCOV),
    ("09", "receipt-hash-mismatch", PASS, NCOV, NCOV, NCOV, PASS),
    ("10", "claim-level-3-without-hash", PASS, NCOV, NCOV, NCOV, DOCS),
    ("11", "stale-approval", PASS, NCOV, NCOV, NCOV, NCOV),
    ("12", "unauthorized-approver", PASS, PART, PART, PART, NCOV),
    ("13", "replay-receipt-id", PASS, PASS, NCOV, PASS, PASS),
    ("14", "completed-before-issued", PASS, PART, NCOV, PASS, NCOV),
    ("15", "policy-version-downgrade", PASS, NCOV, NCOV, NCOV, NCOV),
    ("16", "deny-with-execution-success", PASS, PART, NCOV, PART, PART),
    ("17", "approval-inside-window", PASS, NA, NA, NA, NA),
    ("18", "known-policy-store-passes", PASS, NA, NA, NA, NA),
    ("19", "actor-human-validates", PASS, NCOV, PART, PART, PART),
    ("20", "numeric-arguments-validate", PASS, PASS, NCOV, PASS, NCOV),
    ("21", "multiline-arguments-validate", PASS, PASS, NCOV, PASS, NCOV),
    ("22", "missing-execution-block", PASS, NCOV, NCOV, NCOV, PASS),
    ("23", "malformed-receipt-id", PASS, DOCS, PART, PASS, PASS),
    ("24", "mutated-approver-no-rehash", PASS, NCOV, NCOV, NCOV, NCOV),
    ("25", "clean-receipt-id-passes-replay", PASS, PASS, NCOV, PASS, PASS),
    ("26", "completeness-below-threshold", PASS, DOCS, PASS, PASS, PASS),
    ("27", "completeness-score-mismatch", PASS, PART, PASS, PASS, PASS),
    ("28", "honest-completeness-passes", PASS, PART, PART, PART, PART),
    ("29", "valid-chain-passes", PASS, NCOV, NCOV, NCOV, PASS),
    ("30", "broken-chain-fires", PASS, NCOV, DOCS, DOCS, PASS),
    ("31", "allow-with-blocked-execution", PASS, PART, NCOV, PART, PASS),
    ("32", "fork-chain-shared-prior", PASS, NCOV, NCOV, PART, PASS),
    ("33", "unicode-arguments-validate", PASS, PASS, NCOV, PASS, NCOV),
    ("34", "empty-arguments-validate", PASS, PASS, NCOV, PASS, NCOV),
    ("35", "staging-environment-validates", PASS, NCOV, NCOV, PART, NCOV),
    ("36", "dev-environment-validates", PASS, NCOV, NCOV, PART, NCOV),
    ("37", "execution-failure-with-error-code", PASS, PART, NCOV, PASS, PASS),
    ("38", "approval-without-context", PASS, PASS, PART, PART, NCOV),
    ("39", "nested-arguments-canonical", PASS, PASS, NCOV, PASS, NCOV),
    ("40", "large-arguments-validate", PASS, PASS, NCOV, PASS, NCOV),
)


def tallies() -> dict[str, dict[str, int]]:
    """Return {vendor: {verdict: count}} for the table."""
    out: dict[str, dict[str, int]] = {
        v: {PASS: 0, PART: 0, DOCS: 0, NCOV: 0, NA: 0} for v in VENDORS
    }
    for row in MATRIX:
        verdicts = row[2:]
        for vendor, verdict in zip(VENDORS, verdicts, strict=True):
            out[vendor][verdict] += 1
    return out


# --- SVG layout constants --------------------------------------------

WIDTH = 1180
ROW_H = 24
HEADER_H = 36
PADDING_TOP = 60
PADDING_BOTTOM = 24
LEGEND_H = 56
TALLY_H = 96  # five rows of 16px + label

SCENARIO_COL_W = 380
VENDOR_COL_W = 156  # 5 columns

# Column x positions (relative to the table grid origin at x=PADDING_LEFT)
PADDING_LEFT = 24
TABLE_X = PADDING_LEFT


# Verdict cell styling (light theme; dark-mode pair embedded via @media)
VERDICT_STYLE = {
    PASS: {
        "fill_light": "#dcfce7",
        "fill_dark": "#14532d",
        "text_light": "#166534",
        "text_dark": "#dcfce7",
    },
    PART: {
        "fill_light": "#fef3c7",
        "fill_dark": "#78350f",
        "text_light": "#92400e",
        "text_dark": "#fef3c7",
    },
    DOCS: {
        "fill_light": "#e0e7ff",
        "fill_dark": "#3730a3",
        "text_light": "#3730a3",
        "text_dark": "#e0e7ff",
    },
    NCOV: {
        "fill_light": "#f5f5f4",
        "fill_dark": "#1c1917",
        "text_light": "#78716c",
        "text_dark": "#78716c",
    },
    NA: {
        "fill_light": "#fafaf9",
        "fill_dark": "#0c0a09",
        "text_light": "#a8a29e",
        "text_dark": "#57534e",
    },
}


def build_svg() -> str:
    rows = list(MATRIX)
    n_rows = len(rows)
    table_top = PADDING_TOP + HEADER_H
    table_bottom = table_top + n_rows * ROW_H
    tally_top = table_bottom + 12
    legend_top = tally_top + TALLY_H + 18
    height = legend_top + LEGEND_H + PADDING_BOTTOM

    # Pre-compute cell rectangles
    def vendor_x(idx: int) -> int:
        return TABLE_X + SCENARIO_COL_W + idx * VENDOR_COL_W

    lines: list[str] = []
    lines.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" '
        f'viewBox="0 0 {WIDTH} {height}" role="img" '
        f'aria-label="AgentBoundary conformance matrix — 40 scenarios across JamJet reference and four agent-governance products">'  # noqa: E501
    )
    lines.append(
        "<style>"
        ".bg{fill:#fafaf9}"
        ".fg{fill:#1c1917}"
        ".muted{fill:#57534e}"
        ".accent{fill:#b45309}"
        ".row-band{fill:#fafaf9}"
        ".row-band-alt{fill:#f5f5f4}"
        ".row-divider{stroke:#e7e5e4;stroke-width:1}"
        ".col-divider{stroke:#d6d3d1;stroke-width:1}"
        "@media (prefers-color-scheme: dark){"
        ".bg{fill:#0c0a09}"
        ".fg{fill:#f5f5f4}"
        ".muted{fill:#a8a29e}"
        ".accent{fill:#fbbf24}"
        ".row-band{fill:#0c0a09}"
        ".row-band-alt{fill:#1c1917}"
        ".row-divider{stroke:#292524}"
        ".col-divider{stroke:#44403c}"
        "}"
        'text{font-family:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;font-size:12px}'  # noqa: E501
        ".title{font-size:16px;font-weight:600}"
        ".subtitle{font-size:11px}"
        ".col-header{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.04em}"
        '.scenario-name{font-family:ui-monospace,"SF Mono",Menlo,Monaco,monospace;font-size:11px}'
        '.verdict{font-family:ui-monospace,"SF Mono",Menlo,monospace;font-size:10px;font-weight:600;text-anchor:middle}'  # noqa: E501
        ".tally-label{font-size:11px;font-weight:600}"
        '.tally-num{font-family:ui-monospace,"SF Mono",Menlo,monospace;font-size:11px;text-anchor:middle}'  # noqa: E501
        ".legend{font-size:11px}"
        "</style>"
    )

    lines.append(f'<rect class="bg" width="{WIDTH}" height="{height}"/>')

    # Title + subtitle
    lines.append(
        f'<text class="fg title" x="{PADDING_LEFT}" y="32">'
        "AgentBoundary v0.1 conformance — cross-vendor matrix"
        "</text>"
    )
    lines.append(
        f'<text class="muted subtitle" x="{PADDING_LEFT}" y="50">'
        "40 deterministic scenarios &#x00B7; 4 named products &#x00B7; "
        "docs-only methodology &#x00B7; right-to-respond opened pre-publication"
        "</text>"
    )

    # Column headers
    lines.append(
        f'<text class="muted col-header" x="{PADDING_LEFT}" y="{PADDING_TOP + 20}">'
        "#  scenario"
        "</text>"
    )
    for i, vendor in enumerate(VENDORS):
        x = vendor_x(i) + VENDOR_COL_W // 2
        anchor = "middle"
        lines.append(
            f'<text class="muted col-header" x="{x}" y="{PADDING_TOP + 20}" '
            f'text-anchor="{anchor}">{vendor}</text>'
        )

    # Table rows
    for r_i, (scenario_no, name, *verdicts) in enumerate(rows):
        y_top = table_top + r_i * ROW_H
        y_text = y_top + ROW_H // 2 + 4  # vertical center

        # Alternating row band
        band_class = "row-band" if r_i % 2 == 0 else "row-band-alt"
        lines.append(
            f'<rect class="{band_class}" x="{PADDING_LEFT}" y="{y_top}" '
            f'width="{WIDTH - 2 * PADDING_LEFT}" height="{ROW_H}"/>'
        )

        # Scenario number + name
        scenario_x = PADDING_LEFT + 4
        lines.append(
            f'<text class="fg scenario-name" x="{scenario_x}" y="{y_text}">'
            f"{scenario_no}  {name}"
            f"</text>"
        )

        # Verdict cells
        for v_i, verdict in enumerate(verdicts):
            cell_x = vendor_x(v_i)
            style = VERDICT_STYLE[verdict]
            # Inset the colored rect by 4px on each side
            inset = 4
            rect_x = cell_x + inset
            rect_y = y_top + 4
            rect_w = VENDOR_COL_W - 2 * inset
            rect_h = ROW_H - 8
            lines.append(
                f'<rect x="{rect_x}" y="{rect_y}" width="{rect_w}" '
                f'height="{rect_h}" rx="3" fill="{style["fill_light"]}"/>'
            )
            label = verdict if verdict != NCOV else "—"
            text_x = cell_x + VENDOR_COL_W // 2
            text_y = rect_y + rect_h // 2 + 4
            lines.append(
                f'<text class="verdict" x="{text_x}" y="{text_y}" '
                f'fill="{style["text_light"]}">{label}</text>'
            )

    # Tally rows
    counts = tallies()
    tally_rows = [
        ("PASS", PASS, "#15803d"),
        ("PARTIAL", PART, "#b45309"),
        ("DOCS-ONLY", DOCS, "#4f46e5"),
        ("NOT COVERED", NCOV, "#78716c"),
        ("N/A", NA, "#a8a29e"),
    ]
    # "Total" header
    lines.append(
        f'<text class="muted col-header" x="{PADDING_LEFT}" '
        f'y="{tally_top + 14}">verdict tally</text>'
    )
    for ti, (label, verdict, color) in enumerate(tally_rows):
        y = tally_top + 14 + (ti + 1) * 14
        lines.append(
            f'<text class="tally-label" x="{PADDING_LEFT}" y="{y}" fill="{color}">{label}</text>'
        )
        for vi, vendor in enumerate(VENDORS):
            count = counts[vendor][verdict]
            x = vendor_x(vi) + VENDOR_COL_W // 2
            lines.append(f'<text class="fg tally-num" x="{x}" y="{y}">{count}</text>')

    # Legend
    legend_items = [
        ("PASS", "vendor artifact carries the field; check passes"),
        ("PART", "vendor handles the lifecycle; artifact missing required structure"),
        ("DOCS", "described in docs; cannot be verified from a portable artifact"),
        ("—", "no equivalent in the vendor's normative schema"),
        ("N/A", "positive boundary scenario; semantics don't apply"),
    ]
    lines.append(
        f'<text class="muted col-header" x="{PADDING_LEFT}" y="{legend_top + 16}">legend</text>'
    )
    for i, (label, desc) in enumerate(legend_items):
        y = legend_top + 30 + i * 14
        # color-coded chip
        verdict_key = {
            "PASS": PASS,
            "PART": PART,
            "DOCS": DOCS,
            "—": NCOV,
            "N/A": NA,
        }[label]
        chip_style = VERDICT_STYLE[verdict_key]
        # NB: legend chips are placed horizontally; rewrap two per row
        col = i % 2
        row = i // 2
        chip_x = PADDING_LEFT + col * 520
        chip_y = legend_top + 26 + row * 14
        lines.append(
            f'<rect x="{chip_x}" y="{chip_y}" width="40" height="14" '
            f'rx="2" fill="{chip_style["fill_light"]}"/>'
        )
        lines.append(
            f'<text class="verdict" x="{chip_x + 20}" '
            f'y="{chip_y + 11}" fill="{chip_style["text_light"]}">{label}</text>'
        )
        lines.append(
            f'<text class="muted legend" x="{chip_x + 48}" y="{chip_y + 11}">{desc}</text>'
        )

    lines.append("</svg>")
    return "\n".join(lines) + "\n"


def main() -> None:
    svg = build_svg()
    out_path = Path(__file__).resolve().parent.parent / "docs" / "assets" / "comparative-matrix.svg"
    out_path.write_text(svg, encoding="utf-8")
    print(f"wrote {out_path}")

    counts = tallies()
    print("\nverdict tally per vendor:")
    for vendor in VENDORS:
        c = counts[vendor]
        total = sum(c.values())
        print(
            f"  {vendor:<14s} "
            f"PASS {c[PASS]:>2d}  PART {c[PART]:>2d}  "
            f"DOCS {c[DOCS]:>2d}  NCOV {c[NCOV]:>2d}  N/A {c[NA]:>2d}  "
            f"total {total}"
        )


if __name__ == "__main__":
    main()
