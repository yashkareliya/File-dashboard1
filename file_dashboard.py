# file_dashboard.py
import os
import shutil
import hashlib
import psutil
import pandas as pd
import plotly.express as px
import streamlit as st
from pathlib import Path
from datetime import datetime
import tempfile

# ----------------------------
# App config
# ----------------------------
st.set_page_config(page_title="📁 File Manager & Security Dashboard", layout="wide")
st.sidebar.title("📂 Navigation Menu")

# ----------------------------
# Utility functions
# ----------------------------
def get_available_drives():
    """Return list of available drive mountpoints (Windows/Unix friendly)."""
    drives = []
    try:
        for p in psutil.disk_partitions(all=False):
            if os.path.exists(p.mountpoint):
                drives.append(p.mountpoint)
    except Exception:
        for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            d = f"{letter}:/"
            if os.path.exists(d):
                drives.append(d)
    return drives or [os.path.expanduser("~")]

def get_all_folders(base_path):
    """Return list containing base_path and all nested folders (recursively)."""
    folders = [base_path]
    for root, dirs, _ in os.walk(base_path):
        for d in dirs:
            folders.append(os.path.join(root, d))
    # unique preserve order
    return list(dict.fromkeys(folders))

def list_all_files(folder):
    """Recursively list files and return a DataFrame with details."""
    rows = []
    for root, _, files in os.walk(folder):
        for f in files:
            try:
                p = os.path.join(root, f)
                rows.append({
                    "File Name": f,
                    "Full Path": p,
                    "Folder": Path(root).name,
                    "Size (KB)": round(os.path.getsize(p) / 1024, 2),
                    "Modified": datetime.fromtimestamp(os.path.getmtime(p)).strftime("%Y-%m-%d %H:%M:%S")
                })
            except Exception:
                continue
    return pd.DataFrame(rows)

def safe_name(s: str) -> str:
    """Safe filename/folder base for backups."""
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in s)

# ----------------------------
# Organization operations
# ----------------------------
def organize_by_extension(folder):
    """Move top-level files inside folder into extension-named subfolders."""
    for item in os.listdir(folder):
        p = os.path.join(folder, item)
        if os.path.isfile(p):
            ext = os.path.splitext(item)[1].lstrip(".").upper() or "UNKNOWN"
            dest = os.path.join(folder, safe_name(ext))
            os.makedirs(dest, exist_ok=True)
            try:
                shutil.move(p, os.path.join(dest, item))
            except Exception:
                pass

def organize_by_date(folder):
    """Move top-level files into YYYY-MM folders based on modification date."""
    for item in os.listdir(folder):
        p = os.path.join(folder, item)
        if os.path.isfile(p):
            date = datetime.fromtimestamp(os.path.getmtime(p)).strftime("%Y-%m")
            dest = os.path.join(folder, date)
            os.makedirs(dest, exist_ok=True)
            try:
                shutil.move(p, os.path.join(dest, item))
            except Exception:
                pass

def organize_by_size(folder):
    """Move top-level files into size-range folders."""
    for item in os.listdir(folder):
        p = os.path.join(folder, item)
        if os.path.isfile(p):
            size = os.path.getsize(p)
            if size < 10_000_000:
                name = "Small_0-10MB"
            elif size < 100_000_000:
                name = "Medium_10-100MB"
            else:
                name = "Large_100MB_plus"
            dest = os.path.join(folder, name)
            os.makedirs(dest, exist_ok=True)
            try:
                shutil.move(p, os.path.join(dest, item))
            except Exception:
                pass

# ----------------------------
# Backup & rollback
# ----------------------------
BACKUP_ROOT = Path(tempfile.gettempdir()) / "file_organizer_backups"
BACKUP_ROOT.mkdir(parents=True, exist_ok=True)

def create_backup(folder):
    """
    Create a backup copy of the folder contents (recursive).
    Backup path: BACKUP_ROOT/<safe_folder_name>_<timestamp>/
    """
    base_name = safe_name(Path(folder).name)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = BACKUP_ROOT / f"{base_name}_{ts}"
    try:
        shutil.copytree(folder, backup_path)
    except Exception:
        # fallback best-effort copy
        os.makedirs(backup_path, exist_ok=True)
        for root, dirs, files in os.walk(folder):
            rel = os.path.relpath(root, folder)
            for d in dirs:
                os.makedirs(os.path.join(backup_path, rel, d), exist_ok=True)
            for f in files:
                src = os.path.join(root, f)
                dst = os.path.join(backup_path, rel, f)
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                try:
                    shutil.copy2(src, dst)
                except Exception:
                    pass
    return str(backup_path)

def rollback_from_backup(folder, backup_path):
    """Restore files from backup_path into folder (best-effort)."""
    if not os.path.exists(backup_path):
        return False
    for root, dirs, files in os.walk(backup_path):
        rel = os.path.relpath(root, backup_path)
        for d in dirs:
            os.makedirs(os.path.join(folder, rel, d), exist_ok=True)
        for f in files:
            src = os.path.join(root, f)
            dest = os.path.join(folder, rel, f)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            try:
                if os.path.exists(dest):
                    try:
                        if os.path.isdir(dest):
                            shutil.rmtree(dest)
                        else:
                            os.remove(dest)
                    except Exception:
                        pass
                shutil.copy2(src, dest)
            except Exception:
                pass
    return True

# ----------------------------
# ZIP utilities
# ----------------------------
def create_zip_and_get_path(folder):
    """Create zip next to folder and return full zip path."""
    zip_base = str(Path(folder).with_suffix(""))
    zip_path = shutil.make_archive(zip_base, 'zip', folder)
    return zip_path

# ----------------------------
# Scanner (offline heuristics) + quarantine
# ----------------------------
def file_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

def is_suspicious(path):
    """Heuristic to flag suspicious files."""
    suspicious_exts = {".exe", ".bat", ".vbs", ".js", ".scr", ".cmd", ".dll", ".com", ".pif"}
    ext = Path(path).suffix.lower()
    if ext in suspicious_exts:
        return True
    # double extension like file.txt.exe
    name = Path(path).name
    if name.count(".") > 1 and ext in suspicious_exts:
        return True
    # hidden files (unix-style) or starting with dot
    if name.startswith("."):
        return True
    # optional: very large files might be suspicious
    try:
        if os.path.getsize(path) > 500 * 1024 * 1024:  # >500MB
            return True
    except Exception:
        pass
    return False

def scan_and_quarantine(folder):
    """
    Scan folder recursively for suspicious files.
    Move suspicious files into folder/_quarantine (preserve file name).
    Returns list of moved file absolute paths (destination).
    """
    quarantine = Path(folder) / "_quarantine"
    os.makedirs(quarantine, exist_ok=True)
    moved = []
    for root, _, files in os.walk(folder):
        # skip quarantine and backups
        if "_quarantine" in root or BACKUP_ROOT.name in root:
            continue
        for f in files:
            try:
                p = os.path.join(root, f)
                if is_suspicious(p):
                    # ensure a unique destination (avoid overwrite)
                    dest = quarantine / f
                    i = 1
                    while dest.exists():
                        dest = quarantine / f"{dest.stem}_{i}{dest.suffix}"
                        i += 1
                    shutil.move(p, str(dest))
                    moved.append(str(dest))
            except Exception:
                continue
    return moved

# ----------------------------
# Local scan returning DataFrame (for reporting)
# ----------------------------
def local_scan_report(folder):
    suspicious_exts = {".exe", ".bat", ".vbs", ".js", ".scr", ".cmd", ".dll", ".com", ".pif"}
    rows = []
    for root, _, files in os.walk(folder):
        if "_quarantine" in root or BACKUP_ROOT.name in root:
            continue
        for f in files:
            try:
                p = os.path.join(root, f)
                ext = os.path.splitext(f)[1].lower()
                size_kb = round(os.path.getsize(p) / 1024, 2)
                mtime = datetime.fromtimestamp(os.path.getmtime(p)).strftime("%Y-%m-%d %H:%M:%S")
                h = file_sha256(p)
                status = "Clean"
                reason = "-"
                if ext in suspicious_exts:
                    status = "Suspicious"
                    reason = "Executable/script extension"
                if f.count(".") > 1 and ext in suspicious_exts:
                    status = "Dangerous"
                    reason = "Double extension"
                if f.startswith("."):
                    status = "Hidden"
                    reason = "Hidden file"
                rows.append({
                    "File Name": f,
                    "Path": p,
                    "Extension": ext,
                    "Size (KB)": size_kb,
                    "Modified": mtime,
                    "Hash": h,
                    "Status": status,
                    "Reason": reason
                })
            except Exception:
                continue
    return pd.DataFrame(rows)

# ----------------------------
# System stats helper
# ----------------------------
def get_system_stats():
    cpu = psutil.cpu_percent(interval=1)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage(os.path.abspath(os.sep))
    return {
        "cpu_percent": cpu,
        "ram_total_gb": round(mem.total / (1024**3), 2),
        "ram_used_gb": round(mem.used / (1024**3), 2),
        "ram_percent": mem.percent,
        "disk_total_gb": round(disk.total / (1024**3), 2),
        "disk_used_gb": round(disk.used / (1024**3), 2),
        "disk_free_gb": round(disk.free / (1024**3), 2),
        "disk_percent": disk.percent
    }

# ----------------------------
# UI Navigation
# ----------------------------
menu = st.sidebar.radio("Go to:", ["🏠 Dashboard", "📁 File Organization", "🧠 Scan", "ℹ️ About Us"])

# ----------------------------
# Dashboard
# ----------------------------
if menu == "🏠 Dashboard":
    st.title("📊 System & Folder Dashboard")
    st.markdown("Monitor CPU, RAM, Disk (prefers C: and D: if present) and analyze a selected folder.")

    sys = get_system_stats()
    col1, col2, col3 = st.columns(3)
    col1.metric("💻 CPU Usage", f"{sys['cpu_percent']}%")
    col2.metric("🧠 RAM Used", f"{sys['ram_used_gb']} / {sys['ram_total_gb']} GB", f"{sys['ram_percent']}%")
    col3.metric("💾 Disk Used", f"{sys['disk_used_gb']} / {sys['disk_total_gb']} GB", f"{sys['disk_percent']}%")

    # CPU Progress Bar
    st.markdown("#### 💻 CPU Usage Progress")
    st.progress(sys['cpu_percent'] / 100)
    st.caption(f"Current CPU Usage: {sys['cpu_percent']}%")

# RAM Progress Bar
    st.markdown("#### 🧠 RAM Usage Progress")
    st.progress(sys['ram_percent'] / 100)
    st.caption(f"Memory Used: {sys['ram_used_gb']} GB / {sys['ram_total_gb']} GB ({sys['ram_percent']}%)")


    st.markdown("---")
    st.subheader("💽 Drives")
    detected_drives = get_available_drives()
    # prefer C:, D:
    drives_to_show = []
    for d in ["C:\\", "D:\\"]:
        if d in detected_drives:
            drives_to_show.append(d)
    for d in detected_drives:
        if d not in drives_to_show:
            drives_to_show.append(d)

    disk_rows = []
    for d in drives_to_show:
        try:
            u = psutil.disk_usage(d)
            disk_rows.append({
                "Drive": d,
                "Total (GB)": round(u.total / (1024**3), 2),
                "Used (GB)": round(u.used / (1024**3), 2),
                "Free (GB)": round(u.free / (1024**3), 2),
                "Usage (%)": u.percent
            })
        except Exception:
            continue
    if disk_rows:
        st.dataframe(pd.DataFrame(disk_rows), use_container_width=True)
    else:
        st.info("No drives available to display.")

    st.markdown("---")
    st.subheader("📁 Analyze Folder")
    drives = get_available_drives()
    selected_drive = st.selectbox("Select Drive:", drives)
    folder_choices = get_all_folders(selected_drive)
    selected_folder = st.selectbox("Select Folder to analyze:", folder_choices)

    if selected_folder and Path(selected_folder).exists():
        with st.spinner("Analyzing folder..."):
            df = list_all_files(selected_folder)

        if df.empty:
            st.info("No files found in the selected folder.")
        else:
            total_files = len(df)
            total_folders = df["Folder"].nunique()
            total_size_mb = round(df["Size (KB)"].sum() / 1024, 2)

            m1, m2, m3 = st.columns(3)
            m1.metric("📄 Total Files", total_files)
            m2.metric("📁 Total Folders", total_folders)
            m3.metric("💽 Total Size (MB)", total_size_mb)

            st.markdown("### 🗂 Folder Summary")
            summary = df.groupby("Folder").size().reset_index(name="File Count")
            st.dataframe(summary, use_container_width=True)

            fig = px.bar(summary, x="Folder", y="File Count", text="File Count")
            fig.update_traces(textposition="outside")
            fig.update_layout(xaxis_tickangle=-45, showlegend=False)
            st.plotly_chart(fig, use_container_width=True)

# ----------------------------
# File Organization
# ----------------------------
elif menu == "📁 File Organization":
    st.title("📁 File Organizer")

    drives = get_available_drives()
    selected_drive = st.selectbox("Select Drive:", drives)
    folder_choices = get_all_folders(selected_drive)
    selected_folder = st.selectbox("Select Folder Path:", folder_choices)

    st.info(f"Selected Path: **{selected_folder}**")

    # inline buttons
    c1, c2, c3, c4, c5 = st.columns(5)
    organize_ext_btn = c1.button("📂 Organize by Extension")
    organize_size_btn = c2.button("📏 Organize by Size")
    organize_date_btn = c3.button("🕒 Organize by Date")
    rollback_btn = c4.button("↩️ Rollback")
    zip_btn = c5.button("🗜️ Create ZIP")

    if selected_folder and Path(selected_folder).exists():
        df = list_all_files(selected_folder)
        if not df.empty:
            st.subheader("📄 Files Overview")
            st.dataframe(df, use_container_width=True)
            summary = df.groupby("Folder").size().reset_index(name="File Count")
            st.subheader("📊 Folder Summary")
            st.dataframe(summary, use_container_width=True)
            fig = px.bar(summary, x="Folder", y="File Count", text="File Count", color="Folder")
            fig.update_traces(textposition="outside")
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No files found in this folder.")

    # actions
    if organize_ext_btn:
        if not selected_folder or not os.path.exists(selected_folder):
            st.error("Select a valid folder first.")
        else:
            backup_path = create_backup(selected_folder)
            with st.spinner("Organizing by extension..."):
                organize_by_extension(selected_folder)
            st.success(f"✅ Organized by extension. Backup: {backup_path}")
            st.rerun()

    if organize_size_btn:
        if not selected_folder or not os.path.exists(selected_folder):
            st.error("Select a valid folder first.")
        else:
            backup_path = create_backup(selected_folder)
            with st.spinner("Organizing by size..."):
                organize_by_size(selected_folder)
            st.success(f"✅ Organized by size. Backup: {backup_path}")
            st.rerun()

    if organize_date_btn:
        if not selected_folder or not os.path.exists(selected_folder):
            st.error("Select a valid folder first.")
        else:
            backup_path = create_backup(selected_folder)
            with st.spinner("Organizing by date..."):
                organize_by_date(selected_folder)
            st.success(f"✅ Organized by date. Backup: {backup_path}")
            st.rerun()

    if rollback_btn:
        if not selected_folder or not os.path.exists(selected_folder):
            st.error("Select a valid folder first.")
        else:
            # list backups related to this folder
            pattern = f"{safe_name(Path(selected_folder).name)}_*"
            backups = sorted([str(p) for p in BACKUP_ROOT.glob(pattern)], reverse=True) if 'BACKUP_ROOT' in globals() else []
            # If using create_backup earlier, BACKUP_ROOT exists; otherwise, fallback to temp listing
            if not backups:
                # Attempt to find backups in BACKUP_ROOT
                backups = sorted([str(p) for p in BACKUP_ROOT.glob(pattern)], reverse=True)
            if not backups:
                st.warning("No backups available for this folder.")
            else:
                chosen = st.selectbox("Select a backup to restore:", backups)
                if st.button("Confirm Rollback"):
                    ok = rollback_from_backup(selected_folder, chosen)
                    if ok:
                        st.success("♻️ Rollback completed. Files restored from backup.")
                        st.rerun()
                    else:
                        st.error("❌ Rollback failed.")

    if zip_btn:
        if not selected_folder or not os.path.exists(selected_folder):
            st.error("Select a valid folder first.")
        else:
            with st.spinner("Creating ZIP..."):
                try:
                    zip_path = create_zip_and_get_path(selected_folder)
                    st.success(f"✅ ZIP created: {zip_path}")
                    with open(zip_path, "rb") as f:
                        st.download_button("⬇️ Download ZIP", f, file_name=Path(zip_path).name, mime="application/zip")
                except Exception as e:
                    st.error(f"Failed to create ZIP: {e}")

    # ----------------------------
# Scanner
# ----------------------------
# ----------------------------
# Scanner
# ----------------------------
elif menu == "🧠 Scan":
    st.title("🧠 Local File Scanner (Quarantine Suspicious Files)")

    drives = get_available_drives()
    selected_drive = st.selectbox("Select Drive for Scan:", drives)
    folder_choices = get_all_folders(selected_drive)
    scan_folder = st.selectbox("Select Folder to Scan:", folder_choices)

    scan_btn = st.button("🔍 Start Local Scan")
    if scan_btn:
        if not scan_folder or not os.path.exists(scan_folder):
            st.error("Select a valid folder first.")
        else:
            with st.spinner("Scanning and quarantining suspicious files..."):
                moved = scan_and_quarantine(scan_folder)

            quarantine_path = str(Path(scan_folder) / "_quarantine")

            if moved:
                st.warning(f"⚠️ {len(moved)} suspicious files were moved to: {quarantine_path}")
                st.dataframe(pd.DataFrame({"Quarantined Files": moved}), use_container_width=True)

                # Confirmation before zipping
                if st.button("📦 Create ZIP of Quarantine Folder"):
                    confirm = st.checkbox("✅ Confirm create ZIP of quarantine folder")
                    if confirm:
                        try:
                            quarantine_zip = create_zip_and_get_path(quarantine_path)
                            st.success(f"ZIP created: {quarantine_zip}")
                            with open(quarantine_zip, "rb") as f:
                                st.download_button("⬇️ Download quarantine ZIP", f, file_name=Path(quarantine_zip).name, mime="application/zip")
                        except Exception as e:
                            st.error(f"Failed to create ZIP: {e}")
                    else:
                        st.info("Please confirm before creating the ZIP file.")
            else:
                st.success("✅ No suspicious files found.")

# ----------------------------
# About
# ----------------------------
elif menu == "ℹ️ About Us":
    st.title("ℹ️ About This App")
    st.markdown("""
    **File Organizer & Scanner Dashboard**  
    - Organize files by Extension / Size / Date  
    - Backups created before organizing; restore available via rollback  
    - Scanner moves suspicious files into `_quarantine` (safe isolation)  
    - Create ZIPs of any folder or quarantine for secure archiving  
    - Dynamic drive & folder selection, bar-chart folder summary  
    """)
    st.caption("Built with Streamlit, psutil, and Plotly — 2025")
