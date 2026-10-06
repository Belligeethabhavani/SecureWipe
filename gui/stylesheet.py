from engine.file_wipe import ALGORITHMS

# Map algorithm name → number of passes
PASS_COUNTS = {name: len(passes) for name, passes in ALGORITHMS.items()}

# ── Color palette ───────────────────────────────────────────────────────────
BG           = "#0d1117"   # main background        (near-black)
CARD         = "#161b22"   # card / panel surface
BORDER       = "#30363d"   # subtle borders
TEXT         = "#e6edf3"   # primary text
MUTED        = "#8b949e"   # secondary / muted text
ACCENT       = "#58a6ff"   # blue accent (links, selection)
ACCENT_HOVER = "#79c0ff"
SUCCESS      = "#3fb950"   # green — wipe complete
DANGER       = "#f85149"   # red — wipe/destroy action
DANGER_HOVER = "#ff7b72"
INPUT_BG     = "#0d1117"   # inside text-input areas

STYLESHEET = f"""
/* ── App-wide ── */
QMainWindow, QDialog {{
    background-color: {BG};
    color: {TEXT};
}}

QWidget {{
    background-color: {BG};
    color: {TEXT};
    font-family: "Segoe UI", "Inter", sans-serif;
    font-size: 13px;
}}

/* ── Cards / Panels ── */
QFrame[card="true"] {{
    background-color: {CARD};
    border: 1px solid {BORDER};
    border-radius: 8px;
    padding: 12px;
}}

/* ── Labels ── */
QLabel {{
    color: {TEXT};
    background: transparent;
}}
QLabel[heading="true"] {{
    font-size: 15px;
    font-weight: 600;
    color: {TEXT};
}}
QLabel[muted="true"] {{
    color: {MUTED};
    font-size: 11px;
}}

/* ── Buttons ── */
QPushButton {{
    background-color: {CARD};
    color: {TEXT};
    border: 1px solid {BORDER};
    border-radius: 6px;
    padding: 7px 16px;
    font-weight: 500;
}}
QPushButton:hover {{
    background-color: {BORDER};
    border-color: {ACCENT};
}}
QPushButton[primary="true"] {{
    background-color: {ACCENT};
    color: #0d1117;
    border: none;
    font-weight: 600;
}}
QPushButton[primary="true"]:hover {{
    background-color: {ACCENT_HOVER};
}}
QPushButton[danger="true"] {{
    background-color: {DANGER};
    color: white;
    border: none;
    font-weight: 700;
    font-size: 14px;
    padding: 10px 16px;
}}
QPushButton[danger="true"]:hover {{
    background-color: {DANGER_HOVER};
}}
QPushButton:disabled {{
    background-color: {CARD};
    color: {MUTED};
    border-color: {BORDER};
}}

/* ── Progress bar ── */
QProgressBar {{
    background-color: {INPUT_BG};
    border: 1px solid {BORDER};
    border-radius: 4px;
    height: 14px;
    text-align: center;
    color: {TEXT};
    font-size: 11px;
}}
QProgressBar::chunk {{
    background-color: {ACCENT};
    border-radius: 4px;
}}

/* ── Combo box ── */
QComboBox {{
    background-color: {INPUT_BG};
    border: 1px solid {BORDER};
    border-radius: 6px;
    padding: 5px 10px;
    color: {TEXT};
}}
QComboBox:hover {{
    border-color: {ACCENT};
}}
QComboBox QAbstractItemView {{
    background-color: {CARD};
    selection-background-color: {ACCENT};
    selection-color: #0d1117;
    border: 1px solid {BORDER};
}}
QComboBox::drop-down {{
    border: none;
}}

/* ── List widget ── */
QListWidget {{
    background-color: {INPUT_BG};
    border: 1px solid {BORDER};
    border-radius: 6px;
    color: {TEXT};
    font-size: 12px;
    padding: 4px;
}}
QListWidget::item:selected {{
    background-color: {ACCENT};
    color: #0d1117;
    border-radius: 4px;
}}
QListWidget::item:hover {{
    background-color: {BORDER};
    border-radius: 4px;
}}

/* ── Tab widget ── */
QTabWidget::pane {{
    border: 1px solid {BORDER};
    border-radius: 8px;
    background-color: {CARD};
}}
QTabBar::tab {{
    background-color: {BG};
    color: {MUTED};
    border: 1px solid {BORDER};
    border-bottom: none;
    padding: 7px 20px;
    border-radius: 6px 6px 0 0;
}}
QTabBar::tab:selected {{
    background-color: {CARD};
    color: {ACCENT};
    font-weight: 600;
}}
QTabBar::tab:hover {{
    color: {TEXT};
}}

/* ── Scrollbars ── */
QScrollBar:vertical {{
    background: {BG};
    width: 8px;
    border-radius: 4px;
}}
QScrollBar::handle:vertical {{
    background: {BORDER};
    border-radius: 4px;
    min-height: 20px;
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0;
}}

/* ── Tooltip ── */
QToolTip {{
    background-color: {CARD};
    color: {TEXT};
    border: 1px solid {BORDER};
    border-radius: 4px;
    padding: 4px 8px;
}}
"""
