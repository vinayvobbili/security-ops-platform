const slides = document.querySelector('.slides');
const dots = document.querySelectorAll('.nav-dot');
const pausePlayButton = document.getElementById('pausePlayButton');
let currentSlide = 0;
const totalSlides = document.querySelectorAll('.slides figure').length;
let intervalId; // Variable to store the interval ID

// Start the auto-slide when the page loads
window.addEventListener('load', initializeSlider);
window.addEventListener('resize', updateSlider); // Recalculate on window resize

function initializeSlider() {
    updateSlider(); // Set initial slide position
    playSlideshow(); // Start auto-sliding
}

function playSlideshow() {
    intervalId = setInterval(() => moveSlide(1), 5000);
}

function toggleSlideshow() {
    const srcFileName = pausePlayButton.src.split('/').pop(); // Extract filename
    const isSlideshowRunning = srcFileName === "pause-solid.svg";

    if (isSlideshowRunning) {
        clearInterval(intervalId);
        pausePlayButton.src = "/static/icons/play-solid.svg";
    } else {
        playSlideshow();
        pausePlayButton.src = "/static/icons/pause-solid.svg";
    }
}

// Move to a specific slide
function goToSlide(index) {
    currentSlide = index;
    updateSlider();
}


function showConfetti() {
    // Multiple bursts of confetti for a more exciting effect
    confetti({
        particleCount: 100, spread: 70, origin: {y: 0.6}
    });

    // Additional burst
    setTimeout(() => {
        confetti({
            particleCount: 100, spread: 100, origin: {y: 0.7}
        });
    }, 300);
}

function moveSlide(direction) {
    currentSlide += direction;

    // Wrap around logic
    if (currentSlide >= totalSlides) {
        currentSlide = 0;
    } else if (currentSlide < 0) {
        currentSlide = totalSlides - 1;
    }

    // Check if it's the last slide
    if (currentSlide === totalSlides - 1) {
        showConfetti();
    }

    updateSlider();
}

function updateSlider() {
    const slideWidth = document.querySelector('.slider-container').clientWidth;
    slides.style.transform = `translateX(-${currentSlide * slideWidth}px)`;
    dots.forEach((dot, index) => {
        dot.classList.toggle('active', index === currentSlide);
    });

    if (currentSlide === 0) {
        document.body.classList.remove("show-background");
    } else {
        document.body.classList.add("show-background");
    }
}


document.addEventListener('DOMContentLoaded', () => {
    const music = document.getElementById('music');
    const music_icon = document.getElementById('music-icon');

    music.volume = 0.5; // Set initial volume (0.0 to 1.0)

    function toggleAudio() {
        if (music.muted) {
            music.muted = false;
            music.play();
            music_icon.src = '/static/icons/volume-high-solid.svg';
        } else {
            music.muted = true; // Or music.pause(); if you want to stop playback entirely.
            music_icon.src = '/static/icons/volume-xmark-solid.svg';
        }
    }


    music_icon.addEventListener('click', toggleAudio);
    music.play(); // Start playback muted

});

