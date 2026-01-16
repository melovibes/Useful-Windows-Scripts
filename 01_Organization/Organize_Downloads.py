import os
import shutil
from pathlib import Path
import time

# ================= CONFIGURATION =================
DOWNLOADS_PATH = str(Path.home() / "Downloads")  # Usually works on Windows/Mac/Linux

# You can customize these folders and extensions
FOLDERS = {
    "Images":      [".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".tiff", ".svg"],
    "Videos":      [".mp4", ".mkv", ".webm", ".avi", ".mov", ".flv", ".wmv"],
    "Music":       [".mp3", ".flac", ".wav", ".m4a", ".ogg", ".aac"],
    "Documents":   [".pdf", ".doc", ".docx", ".txt", ".rtf", ".odt", ".md", ".pages"],
    "Archives":    [".zip", ".rar", ".7z", ".tar", ".gz", ".bz2"],
    "Executables": [".exe", ".msi", ".dmg", ".pkg", ".app", ".bat", ".sh"],
    "Code":        [".py", ".js", ".html", ".css", ".java", ".cpp", ".c", ".cs", ".go", ".rs"],
    "Spreadsheets":[".xls", ".xlsx", ".csv", ".ods", ".numbers"],
    "Presentations":[".ppt", ".pptx", ".key"],
    "Torrents":    [".torrent"],
    "DiskImages":  [".iso", ".img"],
}

# Files with these extensions will go to "Other" folder
OTHER_FOLDER = "Other"

# Skip these files/folders (useful to not move this script itself)
SKIP_ITEMS = [
    "desktop.ini",
    ".DS_Store",
    "Organize_Downloads.py",           # change to your script name if different
    "Organize Downloads",              # folder name we will create
]

# ================= MAIN LOGIC =================
def organize_downloads():

    if not os.path.exists(DOWNLOADS_PATH):
        print(f"Downloads folder not found: {DOWNLOADS_PATH}")
        return

    print(f"Organizing: {DOWNLOADS_PATH}\n")

    # Create destination folders if they don't exist
    created_folders = set()

    for category in FOLDERS:
        dest = os.path.join(DOWNLOADS_PATH, category)
        if not os.path.exists(dest):
            os.makedirs(dest)
            created_folders.add(category)

    other_path = os.path.join(DOWNLOADS_PATH, OTHER_FOLDER)
    if not os.path.exists(other_path):
        os.makedirs(other_path)
        created_folders.add(OTHER_FOLDER)

    # Count stats
    moved = 0
    skipped = 0

    # Go through all files in Downloads
    for item in os.listdir(DOWNLOADS_PATH):
        source_path = os.path.join(DOWNLOADS_PATH, item)

        # Skip folders and special files
        if not os.path.isfile(source_path):
            continue

        if item in SKIP_ITEMS:
            print(f"  Skipping protected item: {item}")
            skipped += 1
            continue

        # Get file extension (lowercase)
        _, ext = os.path.splitext(item)
        ext = ext.lower()

        destination_folder = OTHER_FOLDER

        # Find matching category
        for category, extensions in FOLDERS.items():
            if ext in extensions:
                destination_folder = category
                break

        dest_dir = os.path.join(DOWNLOADS_PATH, destination_folder)

        # Handle filename conflicts
        dest_path = os.path.join(dest_dir, item)
        counter = 1
        while os.path.exists(dest_path):
            name, ext = os.path.splitext(item)
            new_name = f"{name} ({counter}){ext}"
            dest_path = os.path.join(dest_dir, new_name)
            counter += 1

        # Move the file
        try:
            shutil.move(source_path, dest_path)
            print(f"Moved → {destination_folder:13} | {item}")
            moved += 1
        except Exception as e:
            print(f"FAILED to move {item} → {e}")
            skipped += 1

    print("\n" + "="*60)
    print(f"Finished! Moved {moved} files | Skipped {skipped} files")
    if created_folders:
        print("Created folders:", ", ".join(sorted(created_folders)))
    print("="*60)


if __name__ == "__main__":
    try:
        organize_downloads()
    except KeyboardInterrupt:
        print("\nStopped by user.")
    except Exception as e:
        print(f"\nAn error occurred: {e}")

    # Small pause so you can see the result
    time.sleep(1.5)
