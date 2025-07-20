// APT Other Names Search Page JavaScript
document.addEventListener('DOMContentLoaded', function() {
    // APT names data from server (will be injected by template)
    // const aptNames = {{ apt_names | tojson }};

    document.getElementById('searchForm').addEventListener('submit', function () {
        document.getElementById('spinner').style.display = 'inline-block';
    });

    // Autocomplete functionality
    const input = document.getElementById('common_name');
    const dropdown = document.getElementById('autocomplete-dropdown');
    let highlightedIndex = -1;
    let filteredNames = [];

    function showDropdown(names) {
        dropdown.innerHTML = '';
        filteredNames = names;

        if (names.length === 0) {
            dropdown.style.display = 'none';
            return;
        }

        names.forEach((name) => {
            const item = document.createElement('div');
            item.className = 'autocomplete-item';
            item.textContent = name;
            item.addEventListener('click', () => {
                input.value = name;
                dropdown.style.display = 'none';
                highlightedIndex = -1;
            });
            dropdown.appendChild(item);
        });

        dropdown.style.display = 'block';
        highlightedIndex = -1;
    }

    function hideDropdown() {
        dropdown.style.display = 'none';
        highlightedIndex = -1;
    }

    function updateHighlight() {
        const items = dropdown.querySelectorAll('.autocomplete-item');
        items.forEach((item, index) => {
            item.classList.toggle('highlighted', index === highlightedIndex);
        });
    }

    input.addEventListener('input', function () {
        const value = this.value.toLowerCase().trim();

        if (value === '') {
            const allNames = window.aptNames.slice(0, 30);
            showDropdown(allNames);
            return;
        }

        const filtered = window.aptNames.filter(name =>
            name.toLowerCase().includes(value)
        ).slice(0, 15);

        showDropdown(filtered);
    });

    input.addEventListener('keydown', function (e) {
        const items = dropdown.querySelectorAll('.autocomplete-item');

        switch (e.key) {
            case 'ArrowDown':
                e.preventDefault();
                highlightedIndex = Math.min(highlightedIndex + 1, items.length - 1);
                updateHighlight();
                break;

            case 'ArrowUp':
                e.preventDefault();
                highlightedIndex = Math.max(highlightedIndex - 1, -1);
                updateHighlight();
                break;

            case 'Enter':
                if (highlightedIndex >= 0 && items[highlightedIndex]) {
                    e.preventDefault();
                    input.value = items[highlightedIndex].textContent;
                    hideDropdown();
                }
                break;

            case 'Escape':
                hideDropdown();
                break;
        }
    });

    input.addEventListener('focus', function () {
        const value = this.value.toLowerCase().trim();

        if (value !== '') {
            const filtered = window.aptNames.filter(name =>
                name.toLowerCase().includes(value)
            ).slice(0, 15);
            showDropdown(filtered);
        }
    });

    // Make the dropdown indicator clickable to show all options
    const dropdownIndicator = document.querySelector('.dropdown-indicator');
    if (dropdownIndicator) {
        dropdownIndicator.style.cursor = 'pointer';
        dropdownIndicator.style.pointerEvents = 'auto';
        dropdownIndicator.addEventListener('click', function (e) {
            e.preventDefault();
            e.stopPropagation();
            input.focus();
            const allNames = window.aptNames.slice(0, 30);
            showDropdown(allNames);
        });
    }

    // Hide dropdown when clicking outside
    document.addEventListener('click', function (e) {
        if (!input.contains(e.target) && !dropdown.contains(e.target)) {
            hideDropdown();
        }
    });

    // Audio functionality
    function toggleAptAudio() {
        var audio = document.getElementById('apt-music');
        var icon = document.getElementById('apt-music-icon');
        if (audio.paused) {
            audio.play();
            icon.src = '/static/icons/volume-high-solid.svg';
            localStorage.setItem('apt-music-playing', 'true');
        } else {
            audio.pause();
            icon.src = '/static/icons/volume-xmark-solid.svg';
            localStorage.setItem('apt-music-playing', 'false');
        }
    }

    // Make toggleAptAudio globally available
    window.toggleAptAudio = toggleAptAudio;

    // Audio initialization - DON'T auto-start music
    var audio = document.getElementById('apt-music');
    var icon = document.getElementById('apt-music-icon');

    // Always start with muted icon - don't auto-play music
    icon.src = '/static/icons/volume-xmark-solid.svg';
    audio.pause(); // Ensure audio is paused

    // Remove auto-start behavior - music should only play when manually clicked
    // var wasPlaying = localStorage.getItem('apt-music-playing') === 'true';
    // if (wasPlaying) { ... } // REMOVED AUTO-START LOGIC

    // Restore current time if available (but don't play)
    var savedTime = parseFloat(localStorage.getItem('apt-music-current-time'));
    if (!isNaN(savedTime)) {
        audio.currentTime = savedTime;
    }

    window.addEventListener('beforeunload', function () {
        localStorage.setItem('apt-music-current-time', audio.currentTime.toString());
    });

    // Response format slider functionality
    const responseFormatSlider = document.getElementById('responseFormatSlider');
    const sliderOptions = document.querySelectorAll('.slider-option');

    responseFormatSlider.addEventListener('click', function() {
        const currentValue = document.getElementById('response_format').value;
        const newValue = currentValue === 'html' ? 'json' : 'html';

        sliderOptions.forEach(opt => opt.classList.remove('active'));
        document.querySelector(`[data-value="${newValue}"]`).classList.add('active');

        if (newValue === 'json') {
            responseFormatSlider.classList.add('json');
        } else {
            responseFormatSlider.classList.remove('json');
        }

        document.getElementById('response_format').value = newValue;
    });

    sliderOptions.forEach(option => {
        option.addEventListener('click', function () {
            const value = this.getAttribute('data-value');

            sliderOptions.forEach(opt => opt.classList.remove('active'));
            this.classList.add('active');

            if (value === 'json') {
                responseFormatSlider.classList.add('json');
            } else {
                responseFormatSlider.classList.remove('json');
            }

            document.getElementById('response_format').value = value;
        });
    });

    // Metadata slider functionality
    const metadataSlider = document.getElementById('metadataSlider');
    const metadataOptions = document.querySelectorAll('.metadata-slider-option');

    metadataSlider.addEventListener('click', function() {
        const currentValue = document.getElementById('should_include_metadata').value;
        const newValue = currentValue === 'true' ? 'false' : 'true';

        metadataOptions.forEach(opt => opt.classList.remove('active'));
        if (newValue === 'true') {
            document.querySelector('[data-value="yes"]').classList.add('active');
            metadataSlider.classList.remove('no');
            metadataSlider.classList.add('yes');
        } else {
            document.querySelector('[data-value="no"]').classList.add('active');
            metadataSlider.classList.remove('yes');
            metadataSlider.classList.add('no');
        }

        document.getElementById('should_include_metadata').value = newValue;
    });

    metadataOptions.forEach(option => {
        option.addEventListener('click', function () {
            const value = this.getAttribute('data-value');

            metadataOptions.forEach(opt => opt.classList.remove('active'));
            this.classList.add('active');

            if (value === 'yes') {
                metadataSlider.classList.remove('no');
                metadataSlider.classList.add('yes');
                document.getElementById('should_include_metadata').value = 'true';
            } else {
                metadataSlider.classList.remove('yes');
                metadataSlider.classList.add('no');
                document.getElementById('should_include_metadata').value = 'false';
            }
        });
    });
});
