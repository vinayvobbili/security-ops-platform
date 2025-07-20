// Falling Notes Animation for APT Results Page
(function () {
    const canvas = document.getElementById('falling-notes-canvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    let width = window.innerWidth;
    let height = window.innerHeight;
    let animationFrameId;

    // Animation control variables
    let animationStartTime = Date.now();
    let animationDuration = 2000; // 2 seconds in milliseconds
    let animationStopped = false;

    // Note shapes/colors
    const noteColors = ['#6a11cb', '#2575fc', '#ff6f61', '#43e97b', '#e74c3c', '#fff', '#222'];
    const noteTypes = ['circle', 'eighth', 'beamed', 'quarter'];

    function randomNoteType() {
        return noteTypes[Math.floor(Math.random() * noteTypes.length)];
    }

    function randomColor() {
        return noteColors[Math.floor(Math.random() * noteColors.length)];
    }

    function resizeCanvas() {
        width = window.innerWidth;
        height = window.innerHeight;
        canvas.width = width;
        canvas.height = height;
    }

    window.addEventListener('resize', resizeCanvas);
    resizeCanvas();

    // Note object
    function createNote() {
        const size = 18 + Math.random() * 18;
        return {
            x: Math.random() * width,
            y: -size,
            size,
            speed: 1.2 + Math.random() * 2.2,
            drift: (Math.random() - 0.5) * 0.7,
            color: randomColor(),
            type: randomNoteType(),
            rotation: Math.random() * Math.PI * 2,
            rotationSpeed: (Math.random() - 0.5) * 0.01
        };
    }

    // Draw a musical note (simple shapes for performance)
    function drawNote(note) {
        ctx.save();
        ctx.translate(note.x, note.y);
        ctx.rotate(note.rotation);
        ctx.globalAlpha = 0.7;
        ctx.strokeStyle = note.color;
        ctx.fillStyle = note.color;
        ctx.lineWidth = 2;
        switch (note.type) {
            case 'circle':
                ctx.beginPath();
                ctx.arc(0, 0, note.size * 0.5, 0, 2 * Math.PI);
                ctx.fill();
                break;
            case 'quarter':
                ctx.beginPath();
                ctx.ellipse(0, 0, note.size * 0.4, note.size * 0.6, 0, 0, 2 * Math.PI);
                ctx.fill();
                ctx.beginPath();
                ctx.moveTo(0, -note.size * 0.6);
                ctx.lineTo(0, -note.size * 1.5);
                ctx.stroke();
                break;
            case 'eighth':
                ctx.beginPath();
                ctx.ellipse(0, 0, note.size * 0.4, note.size * 0.6, 0, 0, 2 * Math.PI);
                ctx.fill();
                ctx.beginPath();
                ctx.moveTo(0, -note.size * 0.6);
                ctx.lineTo(0, -note.size * 1.5);
                ctx.stroke();
                ctx.beginPath();
                ctx.moveTo(0, -note.size * 1.5);
                ctx.quadraticCurveTo(note.size * 0.5, -note.size * 1.7, note.size * 0.7, -note.size * 1.1);
                ctx.stroke();
                break;
            case 'beamed':
                ctx.beginPath();
                ctx.ellipse(-note.size * 0.2, 0, note.size * 0.35, note.size * 0.5, 0, 0, 2 * Math.PI);
                ctx.ellipse(note.size * 0.2, 0, note.size * 0.35, note.size * 0.5, 0, 0, 2 * Math.PI);
                ctx.fill();
                ctx.beginPath();
                ctx.moveTo(-note.size * 0.2, -note.size * 0.5);
                ctx.lineTo(-note.size * 0.2, -note.size * 1.3);
                ctx.moveTo(note.size * 0.2, -note.size * 0.5);
                ctx.lineTo(note.size * 0.2, -note.size * 1.3);
                ctx.stroke();
                ctx.beginPath();
                ctx.moveTo(-note.size * 0.2, -note.size * 1.3);
                ctx.lineTo(note.size * 0.2, -note.size * 1.3);
                ctx.stroke();
                break;
        }
        ctx.globalAlpha = 1;
        ctx.restore();
    }

    // Notes array
    const notes = [];
    const maxNotes = 32;
    let spawnTimer = 0;

    function animate() {
        // Check if 2 seconds have passed
        if (Date.now() - animationStartTime > animationDuration) {
            if (!animationStopped) {
                animationStopped = true;
                // Clear the canvas and stop adding new notes
                ctx.clearRect(0, 0, width, height);
                // Let existing notes finish falling off screen
                if (notes.length === 0) {
                    cancelAnimationFrame(animationFrameId);
                    return;
                }
            }
        }

        ctx.clearRect(0, 0, width, height);

        // Add new notes only if animation hasn't stopped
        spawnTimer++;
        if (!animationStopped && notes.length < maxNotes && spawnTimer % 6 === 0) {
            notes.push(createNote());
        }

        // Animate notes
        for (let i = notes.length - 1; i >= 0; i--) {
            const note = notes[i];
            note.y += note.speed;
            note.x += note.drift;
            note.rotation += note.rotationSpeed;
            drawNote(note);
            // Remove if out of bounds
            if (note.y - note.size > height + 10 || note.x < -50 || note.x > width + 50) {
                notes.splice(i, 1);
            }
        }

        // Continue animation if there are still notes on screen or if not stopped yet
        if (!animationStopped || notes.length > 0) {
            animationFrameId = requestAnimationFrame(animate);
        }
    }

    animate();
})();
