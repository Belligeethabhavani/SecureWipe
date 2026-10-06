import os
import subprocess
import sys
from datetime import datetime

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QProgressBar, QComboBox,
    QFileDialog, QListWidget, QListWidgetItem,
    QMessageBox, QFrame, QTabWidget, QInputDialog,
    QTextEdit, QSplitter, QSizePolicy, QApplication,
    QSpacerItem
)

from engine.file_wipe import wipe_file, wipe_directory, ALGORITHMS, sha256_of_file
from engine.drive_wipe import raw_wipe_physical_drive, logical_to_physical_drive, is_admin
from core.logger import log_event
from core.usb_detect import get_usb_drives
from certificate.generator import generate_certificate
from core.device_info import get_drive_details
from gui.stylesheet import PASS_COUNTS


# ─────────────────────────────────────────────────────────────────────────────
# Background Worker Thread
# ─────────────────────────────────────────────────────────────────────────────

class WipeWorker(QThread):
    # file_idx, total_files, pass_num, total_passes, pass_percent
    progress  = Signal(int, int, int, int, int)
    file_done = Signal(str, str)
    finished  = Signal(dict, str, int)
    error     = Signal(str)

    def __init__(self, file_targets, folder_targets, algorithm):
        super().__init__()
        self.file_targets   = file_targets
        self.folder_targets = folder_targets
        self.algorithm      = algorithm

    def run(self):
        try:
            results   = {}
            all_files = list(self.file_targets)

            for folder in self.folder_targets:
                for root, _, files in os.walk(folder):
                    for fname in files:
                        all_files.append(os.path.join(root, fname))

            total = len(all_files)
            if total == 0:
                self.finished.emit({}, self.algorithm, PASS_COUNTS.get(self.algorithm, 1))
                return

            def make_cb(idx):
                def cb(pass_num, total_passes, pct):
                    self.progress.emit(idx, total, pass_num, total_passes, pct)
                return cb

            for idx, path in enumerate(all_files, start=1):
                h = wipe_file(path, self.algorithm, make_cb(idx))
                results[path] = h
                self.file_done.emit(path, h)

            for folder in self.folder_targets:
                for root, _, _ in os.walk(folder, topdown=False):
                    try:
                        os.rmdir(root)
                    except OSError:
                        pass

            self.finished.emit(results, self.algorithm, PASS_COUNTS.get(self.algorithm, 1))

        except Exception as e:
            self.error.emit(str(e))


class DriveWipeWorker(QThread):
    """
    Background thread for raw physical drive sector wipe.
    Writes directly to \\.\ PHYSICALDRIVEn — all sectors, no filesystem.
    """
    # pass_num, total_passes, bytes_written, total_bytes
    drive_progress = Signal(int, int, int, int)
    drive_finished = Signal(dict)   # summary dict
    error          = Signal(str)

    def __init__(self, physical_path: str, algorithm: str, passes: int):
        super().__init__()
        self.physical_path = physical_path
        self.algorithm     = algorithm
        self.passes        = passes

    def run(self):
        try:
            def cb(pass_num, total_passes, bw, bt):
                self.drive_progress.emit(pass_num, total_passes, bw, bt)

            summary = raw_wipe_physical_drive(
                self.physical_path, self.algorithm, self.passes, progress_cb=cb
            )
            self.drive_finished.emit(summary)
        except Exception as e:
            self.error.emit(str(e))


# ─────────────────────────────────────────────────────────────────────────────
# UI Helpers
# ─────────────────────────────────────────────────────────────────────────────

def card():
    f = QFrame()
    f.setProperty("card", "true")
    return f

def heading(text):
    lbl = QLabel(text)
    lbl.setProperty("heading", "true")
    font = QFont()
    font.setWeight(QFont.Weight.DemiBold)
    lbl.setFont(font)
    return lbl

def muted(text):
    lbl = QLabel(text)
    lbl.setProperty("muted", "true")
    lbl.setWordWrap(True)
    return lbl

def human_size(nbytes):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if nbytes < 1024:
            return f"{nbytes:.1f} {unit}"
        nbytes /= 1024
    return f"{nbytes:.1f} PB"


# ─────────────────────────────────────────────────────────────────────────────
# Main Window  —  Side-by-side layout with QSplitter
# ─────────────────────────────────────────────────────────────────────────────

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SecureWipe  —  NIST SP 800-88")
        self.setMinimumSize(860, 560)

        # Adaptive: 80 % of the available screen
        screen = QApplication.primaryScreen().availableGeometry()
        self.resize(int(screen.width() * 0.80), int(screen.height() * 0.82))

        self.worker      = None
        self.wiping      = False
        self.last_pdf    = None
        self.last_json   = None
        self.drive_targets = {}  # path -> drive_info dict for full-drive wipes
        self._build_ui()

    # ─────────────────────────────────────────────────────────────────────────
    # UI construction
    # ─────────────────────────────────────────────────────────────────────────

    def _build_ui(self):
        root = QWidget()
        root_lay = QVBoxLayout(root)
        root_lay.setSpacing(10)
        root_lay.setContentsMargins(12, 12, 12, 12)

        # ── App header ───────────────────────────────────────────────────────
        header = QHBoxLayout()
        title  = QLabel("🛡  SecureWipe")
        title.setStyleSheet("font-size:22px; font-weight:700;")
        badge = QLabel("NIST SP 800-88  |  DoD 5220.22-M  |  Gutmann")
        badge.setStyleSheet(
            "font-size:10px; font-weight:600; color:#0d1117;"
            "background:#58a6ff; border-radius:4px; padding:3px 12px;"
        )
        header.addWidget(title)
        header.addStretch()
        header.addWidget(badge)
        root_lay.addLayout(header)

        # ── Main splitter: LEFT content | RIGHT control panel ─────────────────
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setHandleWidth(6)
        splitter.setChildrenCollapsible(False)

        # LEFT — tab content
        left_widget = self._build_left_panel()
        splitter.addWidget(left_widget)

        # RIGHT — controls
        right_widget = self._build_right_panel()
        splitter.addWidget(right_widget)

        # Give left 62 %, right 38 %
        splitter.setStretchFactor(0, 62)
        splitter.setStretchFactor(1, 38)

        root_lay.addWidget(splitter, stretch=1)
        self.setCentralWidget(root)

    # ─────────────────────────────────────────────────────────────────────────
    # LEFT PANEL  — tabbed content
    # ─────────────────────────────────────────────────────────────────────────

    def _build_left_panel(self):
        w   = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 4, 0)
        lay.setSpacing(0)

        self.tabs = QTabWidget()
        self.tabs.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.tabs.addTab(self._build_files_tab(),  "  Files & Folders  ")
        self.tabs.addTab(self._build_usb_tab(),    "  USB Devices  ")
        self.tabs.addTab(self._build_verify_tab(), "  Verify Certificate  ")
        self.tabs.addTab(self._build_about_tab(),  "  About  ")
        lay.addWidget(self.tabs)
        return w

    def _build_files_tab(self):
        w   = QWidget()
        lay = QVBoxLayout(w)
        lay.setSpacing(8)
        lay.setContentsMargins(6, 10, 6, 6)

        c   = card()
        cl  = QVBoxLayout(c)
        cl.addWidget(heading("Target Files & Folders"))
        cl.addWidget(muted(
            "Add files or folders. Click any item to preview its SHA-256 — "
            "this hash is recorded in the wipe certificate as proof of what existed."
        ))

        self.file_list = QListWidget()
        self.file_list.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.file_list.setSelectionMode(QListWidget.SelectionMode.ExtendedSelection)
        cl.addWidget(self.file_list, stretch=1)

        btn_row = QHBoxLayout()
        for label, slot, primary in [
            ("＋ Add Files",  self.add_files,          True),
            ("📁 Add Folder", self.add_folder,          False),
            ("✕ Remove",      self.remove_selected,     False),
            ("Clear All",     self.file_list.clear,     False),
        ]:
            b = QPushButton(label)
            if primary:
                b.setProperty("primary", "true")
            b.clicked.connect(slot)
            btn_row.addWidget(b)
        cl.addLayout(btn_row)
        lay.addWidget(c, stretch=1)
        return w

    def _build_usb_tab(self):
        w   = QWidget()
        lay = QVBoxLayout(w)
        lay.setSpacing(8)
        lay.setContentsMargins(6, 10, 6, 6)

        c  = card()
        cl = QVBoxLayout(c)
        cl.addWidget(heading("Connected USB / External Drives"))
        cl.addWidget(muted(
            "Removable drives appear below automatically. "
            "Browse a drive to pick individual files, or add the whole drive as a folder target."
        ))

        self.usb_list = QListWidget()
        self.usb_list.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        cl.addWidget(self.usb_list, stretch=1)

        row = QHBoxLayout()
        for label, slot, primary in [
            ("🔄 Refresh",                   self.refresh_usb,       True),
            ("📂 Browse → Add Files",        self.browse_usb_drive,  False),
            ("💾 Wipe Full Device",          self.wipe_usb_drive,    False),
        ]:
            b = QPushButton(label)
            if primary:
                b.setProperty("primary", "true")
            b.clicked.connect(slot)
            row.addWidget(b)
        cl.addLayout(row)

        self.usb_info = muted("Select a drive to see details.")
        cl.addWidget(self.usb_info)
        lay.addWidget(c, stretch=1)

        self.usb_list.currentItemChanged.connect(self._show_usb_info)
        self.refresh_usb()
        return w

    def _build_verify_tab(self):
        import os
        w   = QWidget()
        lay = QVBoxLayout(w)
        lay.setSpacing(10)
        lay.setContentsMargins(6, 10, 6, 6)

        c  = card()
        cl = QVBoxLayout(c)
        cl.setSpacing(12)

        cl.addWidget(heading("Verify a SecureWipe Certificate"))
        cl.addWidget(muted(
            "Verification is done entirely in your browser using the Web Crypto API "
            "— no internet, no server, pure Ed25519 math."
        ))

        # Step-by-step instructions
        steps = QLabel("""
<ol style="line-height:2; color:#c9d1d9;">
  <li>Open the PDF certificate (it was saved to your Desktop after wipe)</li>
  <li>Click <b>Open Verifier</b> below — this opens <code>verify.html</code> in your browser</li>
  <li>Drag &amp; drop the PDF onto the upload zone</li>
  <li>Paste the <b>Device Public Key</b> printed on page&nbsp;1 of the certificate</li>
  <li>Click <b>Verify Certificate</b> — the browser hashes the PDF and checks the Ed25519 signature</li>
</ol>""")
        steps.setTextFormat(Qt.TextFormat.RichText)
        steps.setWordWrap(True)
        cl.addWidget(steps)

        # Open verifier button
        open_verify_btn = QPushButton("🌐  Open Verifier  (verify.html)")
        open_verify_btn.setProperty("primary", "true")
        open_verify_btn.setMinimumHeight(42)
        open_verify_btn.clicked.connect(self.open_verifier)
        cl.addWidget(open_verify_btn)

        note = QLabel(
            "<i style='color:#8b949e;'>verify.html is located in the SecureWipe application folder. "
            "It runs offline — no data leaves your device.</i>"
        )
        note.setTextFormat(Qt.TextFormat.RichText)
        note.setWordWrap(True)
        cl.addWidget(note)

        cl.addStretch()
        lay.addWidget(c, stretch=1)
        return w

    def _build_about_tab(self):
        w   = QWidget()
        lay = QVBoxLayout(w)
        lay.setSpacing(8)
        lay.setContentsMargins(6, 10, 6, 6)

        c  = card()
        cl = QVBoxLayout(c)

        content = QLabel("""
<h2>🛡 SecureWipe v2.0</h2>
<p style="color:#8b949e;">Industry-grade secure file deletion</p>
<hr style="border-color:#30363d;"/>

<h3>Standards Compliance</h3>
<ul>
  <li><b>NIST SP 800-88 Rev. 1</b> — Guidelines for Media Sanitization</li>
  <li><b>DoD 5220.22-M</b> — 3-pass overwrite (random → ones → zero)</li>
  <li><b>Gutmann (7-pass)</b> — maximum assurance wipe</li>
</ul>

<h3>How It Works</h3>
<ol>
  <li>SHA-256 of original file is recorded as pre-wipe proof</li>
  <li>File overwritten with multiple passes (random/zero/ones data)</li>
  <li><code>fsync()</code> called after each pass (forces physical disk write)</li>
  <li>File truncated to 0 bytes, renamed to UUID, then deleted</li>
</ol>

<h3>Third-Party Verification</h3>
<p>Every wipe produces a <b>PDF certificate</b> + <b>JSON sidecar</b>. The JSON stores a
SHA-256 of the PDF, making it tamper-evident. Load the JSON in the
<i>Verify Certificate</i> tab to confirm data was genuinely destroyed — ideal
for selling used SSDs or compliance audits.</p>

<h3>Audit Log</h3>
<p>All events are logged to <code>securewipe_audit.log</code>. Each entry is chained
to the previous one via SHA-256, making the log tamper-evident.</p>

<hr style="border-color:#30363d;"/>
<p style="color:#8b949e; font-size:11px;">
SecureWipe v2.0 &nbsp;|&nbsp; NIST SP 800-88 Rev.1 &nbsp;|&nbsp; DoD 5220.22-M &nbsp;|&nbsp; Gutmann<br/>
Built with PySide6 · ReportLab · psutil
</p>
        """)
        content.setTextFormat(Qt.TextFormat.RichText)
        content.setWordWrap(True)
        content.setAlignment(Qt.AlignmentFlag.AlignTop)
        cl.addWidget(content)
        cl.addStretch()
        lay.addWidget(c, stretch=1)
        return w

    # ─────────────────────────────────────────────────────────────────────────
    # RIGHT PANEL  — item info + algorithm + wipe button + progress
    # ─────────────────────────────────────────────────────────────────────────

    def _build_right_panel(self):
        w   = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(4, 0, 0, 0)
        lay.setSpacing(10)

        # ── Item Info card ───────────────────────────────────────────────────
        info_card = card()
        il = QVBoxLayout(info_card)
        il.addWidget(heading("Item Info"))
        self.info_name = muted("Name: —")
        self.info_size = muted("Size: —")
        self.info_type = muted("Type: —")
        self.info_mod  = muted("Modified: —")
        self.info_hash = muted("SHA-256: —")
        for lbl in (self.info_name, self.info_size, self.info_type, self.info_mod, self.info_hash):
            il.addWidget(lbl)
        lay.addWidget(info_card)

        # ── Algorithm card ───────────────────────────────────────────────────
        algo_card = card()
        al = QVBoxLayout(algo_card)
        al.addWidget(heading("Wipe Algorithm"))
        al.addWidget(muted("Choose the overwrite standard to use."))
        self.algo_combo = QComboBox()
        self.algo_combo.addItems(list(ALGORITHMS.keys()))
        self.algo_combo.setCurrentIndex(1)
        self.algo_combo.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.algo_combo.currentTextChanged.connect(self._update_pass_info)
        al.addWidget(self.algo_combo)
        self.pass_info = muted("")
        al.addWidget(self.pass_info)
        self._update_pass_info(self.algo_combo.currentText())
        lay.addWidget(algo_card)

        # ── Wipe button ──────────────────────────────────────────────────────
        self.wipe_btn = QPushButton("🗑   Start Secure Wipe")
        self.wipe_btn.setProperty("danger", "true")
        self.wipe_btn.setMinimumHeight(48)
        self.wipe_btn.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.wipe_btn.clicked.connect(self.start_wipe)
        lay.addWidget(self.wipe_btn)

        # ── Progress card ────────────────────────────────────────────────────
        prog_card = card()
        pl = QVBoxLayout(prog_card)
        pl.addWidget(heading("Progress"))

        pl.addWidget(muted("Overall"))
        self.overall_bar = QProgressBar()
        self.overall_bar.setValue(0)
        self.overall_bar.setFormat("—")
        pl.addWidget(self.overall_bar)

        pl.addWidget(muted("Current Pass"))
        self.pass_bar = QProgressBar()
        self.pass_bar.setValue(0)
        self.pass_bar.setFormat("—")
        pl.addWidget(self.pass_bar)

        self.status_lbl = muted("Idle — add files and press Start Wipe")
        pl.addWidget(self.status_lbl)
        lay.addWidget(prog_card)

        # ── Open Certificate button (hidden until wipe done) ─────────────────
        self.open_cert_btn = QPushButton("📄  Open Certificate")
        self.open_cert_btn.setProperty("primary", "true")
        self.open_cert_btn.setMinimumHeight(36)
        self.open_cert_btn.setVisible(False)
        self.open_cert_btn.clicked.connect(self.open_certificate)
        lay.addWidget(self.open_cert_btn)

        lay.addStretch()

        # Connect file list click → update Item Info in right panel
        self.file_list.currentItemChanged.connect(self._show_file_info)

        return w

    # ─────────────────────────────────────────────────────────────────────────
    # Actions — Files
    # ─────────────────────────────────────────────────────────────────────────

    def add_files(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Select Files to Wipe")
        for f in files:
            self._add_path(f, is_dir=False)

    def add_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Folder to Wipe")
        if folder:
            self._add_path(folder, is_dir=True)

    def _add_path(self, path, is_dir):
        existing = [self.file_list.item(i).data(Qt.ItemDataRole.UserRole)
                    for i in range(self.file_list.count())]
        if path in existing:
            return
        if is_dir:
            n     = sum(len(fs) for _, _, fs in os.walk(path))
            label = f"📁  {os.path.basename(path)}   ({n} files)"
        else:
            label = f"📄  {os.path.basename(path)}   [{human_size(os.path.getsize(path))}]"
        item = QListWidgetItem(label)
        item.setData(Qt.ItemDataRole.UserRole,     path)
        item.setData(Qt.ItemDataRole.UserRole + 1, is_dir)
        self.file_list.addItem(item)

    def remove_selected(self):
        for item in self.file_list.selectedItems():
            self.file_list.takeItem(self.file_list.row(item))

    def _show_file_info(self, current, _prev):
        if not current:
            return
        path   = current.data(Qt.ItemDataRole.UserRole)
        is_dir = current.data(Qt.ItemDataRole.UserRole + 1)
        if is_dir:
            self.info_name.setText(f"Name: {os.path.basename(path)}")
            self.info_size.setText("Size: calculated at wipe time")
            self.info_type.setText("Type: Directory")
            self.info_mod.setText(f"Modified: {datetime.fromtimestamp(os.path.getmtime(path))}")
            self.info_hash.setText("SHA-256: computed per-file during wipe")
        elif os.path.isfile(path):
            ext = os.path.splitext(path)[1] or "(unknown)"
            self.info_name.setText(f"Name: {os.path.basename(path)}")
            self.info_size.setText(f"Size: {human_size(os.path.getsize(path))}")
            self.info_type.setText(f"Type: {ext}")
            self.info_mod.setText(f"Modified: {datetime.fromtimestamp(os.path.getmtime(path))}")
            self.info_hash.setText("SHA-256: computing…")
            sha = sha256_of_file(path)
            self.info_hash.setText(f"SHA-256:\n{sha[:32]}\n{sha[32:]}")

    # ─────────────────────────────────────────────────────────────────────────
    # Actions — USB
    # ─────────────────────────────────────────────────────────────────────────

    def refresh_usb(self):
        self.usb_list.clear()
        drives = get_usb_drives()
        if not drives:
            self.usb_list.addItem("No removable drives detected — plug in a USB drive and refresh.")
            return
        for d in drives:
            label = (f"💾  {d['device']}  [{d['fstype']}]  "
                     f"{d['free_gb']:.1f} GB free / {d['total_gb']:.1f} GB")
            item  = QListWidgetItem(label)
            item.setData(Qt.ItemDataRole.UserRole, d)
            self.usb_list.addItem(item)

    def _show_usb_info(self, current, _prev):
        if not current:
            return
        d = current.data(Qt.ItemDataRole.UserRole)
        if not d:
            return
        self.usb_info.setText(
            f"Drive: {d['device']}  |  FS: {d['fstype']}  |  "
            f"Total: {d['total_gb']:.2f} GB  |  Free: {d['free_gb']:.2f} GB"
        )

    def browse_usb_drive(self):
        item = self.usb_list.currentItem()
        if not item or not item.data(Qt.ItemDataRole.UserRole):
            QMessageBox.information(self, "USB", "Select a drive from the list first.")
            return
        d = item.data(Qt.ItemDataRole.UserRole)
        files, _ = QFileDialog.getOpenFileNames(self, "Select Files from Drive", d["mountpoint"])
        for f in files:
            self._add_path(f, is_dir=False)
        if files:
            self.tabs.setCurrentIndex(0)

    def wipe_usb_drive(self):
        item = self.usb_list.currentItem()
        if not item or not item.data(Qt.ItemDataRole.UserRole):
            QMessageBox.information(self, "USB", "Select a drive from the list first.")
            return
        d     = item.data(Qt.ItemDataRole.UserRole)
        algo  = self.algo_combo.currentText()
        passes = PASS_COUNTS.get(algo, 1)

        drive_info          = get_drive_details(d["mountpoint"])
        drive_info["model"] = d.get("model", "")
        entry = {"drive_dict": d, "info": drive_info}
        self._start_raw_drive_wipe_entry(d["mountpoint"], entry, algo, passes)


    def _start_raw_drive_wipe_entry(self, mount, entry, algo, passes):
        """Admin check, confirmation, then kick off DriveWipeWorker."""
        if not is_admin():
            QMessageBox.critical(self, "⛔ Administrator Required",
                "Raw drive wipe requires Administrator privileges.\n\n"
                "Please restart SecureWipe as Administrator\n"
                "(right-click → Run as administrator).")
            return

        d          = entry["drive_dict"]
        drive_info = entry["info"]
        model      = d.get("model", "Unknown") or d["device"]
        total      = d.get("total_gb", 0)

        try:
            physical_path = logical_to_physical_drive(mount)
        except Exception as e:
            QMessageBox.critical(self, "Drive Mapping Failed", str(e))
            return

        confirm = QMessageBox.warning(self, "⚠️  Raw Drive Wipe — IRREVERSIBLE",
            f"You are about to perform a RAW SECTOR WIPE on:\n\n"
            f"  Drive:    {d['device']}  ({mount})\n"
            f"  Model:    {model}\n"
            f"  Capacity: {total:.1f} GB\n"
            f"  Physical: {physical_path}\n\n"
            f"  Algorithm: {algo}  |  {passes} pass(es)\n\n"
            "This writes to EVERY sector  —  deleted files, slack space,\n"
            "unallocated clusters, MFT — all overwritten.\n\n"
            "⚠️  ALL DATA ON THIS DRIVE WILL BE PERMANENTLY DESTROYED.\n"
            "     This cannot be undone.\n\n"
            "Are you absolutely sure?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel)

        if confirm != QMessageBox.StandardButton.Yes:
            self.status_lbl.setText("Raw wipe cancelled.")
            return

        drive_info["physical_drive"] = physical_path

        self._reset_progress()
        self._set_wiping(True)
        self.open_cert_btn.setVisible(False)
        self.overall_bar.setRange(0, 100)
        self.pass_bar.setRange(0, 100)
        self.status_lbl.setText(f"⚡ Raw sector wipe: {physical_path}  ({total:.1f} GB)…")

        self.drive_worker = DriveWipeWorker(physical_path, algo, passes)
        self.drive_worker.drive_progress.connect(self._on_drive_progress)
        self.drive_worker.drive_finished.connect(
            lambda summary: self._on_drive_finished(summary, drive_info, algo, passes))
        self.drive_worker.error.connect(self._on_drive_error)
        self.drive_worker.start()

    def _on_drive_progress(self, pass_num, total_passes, bw, bt):
        if bt > 0:
            pct = int(bw * 100 / bt)
            self.pass_bar.setValue(pct)
            self.pass_bar.setFormat(f"Pass {pass_num+1}/{total_passes}  —  {pct}%")
            overall = int((pass_num * 100 + pct) / total_passes)
            self.overall_bar.setValue(overall)
            gb_done = bw / (1024**3)
            gb_tot  = bt / (1024**3)
            self.status_lbl.setText(
                f"⚡ Pass {pass_num+1}/{total_passes}  —  {gb_done:.2f} / {gb_tot:.2f} GB")

    def _on_drive_finished(self, summary, drive_info, algo, passes):
        self.overall_bar.setValue(100)
        self.overall_bar.setFormat("Complete ✓")
        self.pass_bar.setValue(100)
        self.pass_bar.setFormat("Complete ✓")
        self.status_lbl.setText("✅  Raw drive wipe complete.")
        self._set_wiping(False)

        log_event("RAW_DRIVE_WIPE_COMPLETE", summary.get("physical_drive", ""))

        try:
            suggested = f"SecureWipe_Certificate_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            pdf_path, _ = QFileDialog.getSaveFileName(self, "Save Certificate", suggested, "PDF Files (*.pdf)")
            
            if not pdf_path:
                self.open_cert_btn.setVisible(False)
                return

            res, = generate_certificate(
                {summary["physical_drive"]: "raw_sector_wipe"},
                algo, passes,
                output_path=pdf_path,
                storage_devices=[drive_info]
            )
            self.last_pdf = res
            self.open_cert_btn.setVisible(True)
            QMessageBox.information(self, "✅  Drive Wipe Complete",
                f"Raw sector wipe finished.\n\n"
                f"Drive: {summary['physical_drive']}\n"
                f"Capacity: {summary.get('total_gb', 0):.2f} GB\n"
                f"Algorithm: {algo}  |  {passes} passes\n\n"
                f"Certificate saved to:\n{res}\n\n"
                "Scan the QR code on the certificate to verify."
            )
        except Exception as e:
            QMessageBox.warning(self, "Certificate Error",
                f"Drive wiped successfully but certificate failed:\n{e}")

    def _on_drive_error(self, msg):
        self._set_wiping(False)
        QMessageBox.critical(self, "❌ Raw Wipe Failed", msg)


    # ─────────────────────────────────────────────────────────────────────────
    # Actions — Verify Certificate
    # ─────────────────────────────────────────────────────────────────────────

    def open_verifier(self):
        import subprocess
        verify_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "..", "verify.html"
        )
        verify_path = os.path.normpath(verify_path)
        if os.path.isfile(verify_path):
            os.startfile(verify_path)
        else:
            QMessageBox.warning(self, "Not Found",
                f"verify.html not found at:\n{verify_path}")

    # ─────────────────────────────────────────────────────────────────────────
    # Algorithm info
    # ─────────────────────────────────────────────────────────────────────────

    def _update_pass_info(self, algo_name):
        passes = ALGORITHMS.get(algo_name, [])
        self.pass_info.setText(
            f"{len(passes)} pass{'es' if len(passes) != 1 else ''}:  "
            + "  →  ".join(p.upper() for p in passes)
        )

    # ─────────────────────────────────────────────────────────────────────────
    # Wipe flow
    # ─────────────────────────────────────────────────────────────────────────

    def start_wipe(self):
        if self.wiping:
            return

        items = [self.file_list.item(i) for i in range(self.file_list.count())]
        if not items:
            QMessageBox.warning(self, "Nothing to wipe", "Add at least one file or folder first.")
            return

        algo  = self.algo_combo.currentText()
        text, ok = QInputDialog.getText(
            self,
            "⚠  Confirm Irreversible Wipe",
            f"About to permanently destroy {len(items)} item(s)\n"
            f"using {algo}.\n\n"
            "This CANNOT be undone.\n\nType  WIPE  to confirm:",
        )
        if not ok or text.strip().upper() != "WIPE":
            self.status_lbl.setText("Wipe cancelled.")
            return

        file_targets   = []
        folder_targets = []
        for item in items:
            path   = item.data(Qt.ItemDataRole.UserRole)
            is_dir = item.data(Qt.ItemDataRole.UserRole + 1)
            (folder_targets if is_dir else file_targets).append(path)

        self._reset_progress()
        self._set_wiping(True)
        self.open_cert_btn.setVisible(False)

        log_event("WIPE_STARTED", f"algorithm={algo}, files={len(file_targets)}, folders={len(folder_targets)}")

        self.worker = WipeWorker(file_targets, folder_targets, algo)
        self.worker.progress.connect(self._on_progress)
        self.worker.file_done.connect(self._on_file_done)
        self.worker.finished.connect(self._on_finished)
        self.worker.error.connect(self._on_error)
        self.worker.start()

    def _reset_progress(self):
        self.overall_bar.setValue(0)
        self.overall_bar.setFormat("—")
        self.pass_bar.setValue(0)
        self.pass_bar.setFormat("—")

    def _set_wiping(self, active):
        self.wiping = active
        self.wipe_btn.setEnabled(not active)
        self.wipe_btn.setText("⏳  Wiping…" if active else "🗑   Start Secure Wipe")

    def _on_progress(self, file_idx, total_files, pass_num, total_passes, pass_pct):
        self.overall_bar.setMaximum(total_files)
        self.overall_bar.setValue(file_idx - 1)
        self.overall_bar.setFormat(f"File {file_idx} of {total_files}")
        self.pass_bar.setValue(pass_pct)
        self.pass_bar.setFormat(f"Pass {pass_num}/{total_passes}  —  {pass_pct}%")
        self.status_lbl.setText(
            f"Wiping {file_idx}/{total_files}  ·  Pass {pass_num}/{total_passes}  ·  {pass_pct}%"
        )

    def _on_file_done(self, path, sha):
        name = os.path.basename(path)
        for i in range(self.file_list.count()):
            item = self.file_list.item(i)
            if (item.data(Qt.ItemDataRole.UserRole) == path
                    and not item.text().startswith("✅")):
                item.setText(f"✅  {name}  (wiped)")
                item.setForeground(Qt.GlobalColor.gray)
                break

    def _on_finished(self, wiped_files, algorithm, passes):
        log_event("WIPE_COMPLETED", f"files={len(wiped_files)}, algorithm={algorithm}")
        n = len(wiped_files)
        self.overall_bar.setMaximum(max(n, 1))
        self.overall_bar.setValue(n)
        self.overall_bar.setFormat(f"Done — {n} file(s)")
        self.pass_bar.setValue(100)
        self.pass_bar.setFormat("Complete ✓")
        self.status_lbl.setText(f"✅  {n} file(s) securely destroyed.")
        self._set_wiping(False)

        try:
            suggested = f"SecureWipe_Certificate_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            pdf_path, _ = QFileDialog.getSaveFileName(self, "Save Certificate", suggested, "PDF Files (*.pdf)")
            
            if not pdf_path:
                self.drive_targets.clear()
                self.open_cert_btn.setVisible(False)
                return

            res, = generate_certificate(
                wiped_files, algorithm, passes,
                output_path=pdf_path,
                storage_devices=list(self.drive_targets.values()) or None
            )
            self.last_pdf = res
            self.drive_targets.clear()  # reset after cert
            log_event("CERTIFICATE_GENERATED", res)
            self.open_cert_btn.setVisible(True)

            QMessageBox.information(self, "✅  Wipe Complete",
                f"{n} file(s) permanently destroyed.\n\n"
                f"Algorithm: {algorithm}  |  {passes} passes\n\n"
                f"Signed PDF certificate saved to:\n{pdf_path}\n\n"
                f"Scan the QR code on the certificate to verify."
            )
        except Exception as e:
            QMessageBox.warning(self, "Certificate Error",
                f"Wipe succeeded but certificate failed:\n{e}")

        self.file_list.clear()

    def _on_error(self, message):
        log_event("WIPE_ERROR", message, level="ERROR")
        self.status_lbl.setText(f"❌  Error: {message}")
        self._set_wiping(False)
        QMessageBox.critical(self, "Wipe Error", f"An error occurred:\n\n{message}")

    # ─────────────────────────────────────────────────────────────────────────
    # Open certificate
    # ─────────────────────────────────────────────────────────────────────────

    def open_certificate(self):
        if not self.last_pdf or not os.path.isfile(self.last_pdf):
            QMessageBox.warning(self, "Not Found", "Certificate file not found.")
            return
        if sys.platform == "win32":
            os.startfile(self.last_pdf)
        elif sys.platform == "darwin":
            subprocess.run(["open", self.last_pdf])
        else:
            subprocess.run(["xdg-open", self.last_pdf])