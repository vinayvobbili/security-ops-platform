#!/bin/zsh
# Stage browser history database files for RTR download on macOS.
# Copies browser history SQLite databases to a temp location since
# the originals may be locked by the browser process.

staging_dir="/tmp/BH"
rm -rf "$staging_dir"
mkdir -p "$staging_dir"

count=0

echo "STAGED_FILES_START"

for user_home in /Users/*/; do
    uname=$(basename "$user_home")
    # Skip system/service accounts
    if [[ "$uname" == "Shared" || "$uname" == ".localized" || "$uname" == "Guest" ]]; then
        continue
    fi

    # Chrome Default
    src="$user_home/Library/Application Support/Google/Chrome/Default/History"
    if [[ -f "$src" ]]; then
        dest="$staging_dir/Chrome_${uname}.db"
        cp "$src" "$dest" 2>/dev/null
        if [[ -f "$dest" ]]; then
            echo "Chrome|${uname}|${dest}"
            count=$((count + 1))
        fi
    fi

    # Edge Default
    src="$user_home/Library/Application Support/Microsoft Edge/Default/History"
    if [[ -f "$src" ]]; then
        dest="$staging_dir/Edge_${uname}.db"
        cp "$src" "$dest" 2>/dev/null
        if [[ -f "$dest" ]]; then
            echo "Edge|${uname}|${dest}"
            count=$((count + 1))
        fi
    fi

    # Firefox (first profile only)
    ff_profiles="$user_home/Library/Application Support/Firefox/Profiles"
    if [[ -d "$ff_profiles" ]]; then
        ff_profile=$(ls -d "$ff_profiles"/*/ 2>/dev/null | head -1)
        if [[ -n "$ff_profile" ]]; then
            src="${ff_profile}places.sqlite"
            if [[ -f "$src" ]]; then
                dest="$staging_dir/Firefox_${uname}.db"
                cp "$src" "$dest" 2>/dev/null
                if [[ -f "$dest" ]]; then
                    echo "Firefox|${uname}|${dest}"
                    count=$((count + 1))
                fi
            fi
        fi
    fi

    # Safari
    src="$user_home/Library/Safari/History.db"
    if [[ -f "$src" ]]; then
        dest="$staging_dir/Safari_${uname}.db"
        cp "$src" "$dest" 2>/dev/null
        if [[ -f "$dest" ]]; then
            echo "Safari|${uname}|${dest}"
            count=$((count + 1))
        fi
    fi
done

echo "STAGED_FILES_END"

if [[ "$count" -eq 0 ]]; then
    echo "NO_HISTORY_FILES_FOUND"
else
    echo "Staged $count files to $staging_dir"
fi
