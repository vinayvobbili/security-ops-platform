/**
 * Meeting Minutes QA — frontend logic
 * Handles analysis requests, result parsing/rendering, and PDF export.
 */
(function () {
    'use strict';

    var STORAGE_KEY = 'meetingQA_draft';

    /* ---- DOM refs ---- */
    var humanNotes, copilotNotes, analyzeBtn, clearBtn, exportBtn, statusText;
    var resultsSection, scoreCards, comparisonContent, minutesContent, scoresDetailContent;
    var humanWordCount, copilotWordCount;

    /* ---- Tracker state ---- */
    var trackerEl, trackerStatusEl, trackerJokeEl;
    var trackerInterval = null;
    var trackerStartTime = 0;
    var trackerJokeIndex = 0;
    var EXPECTED_DURATION = 90; // seconds (~1 min typical)
    var RING_CIRCUMFERENCE = 2 * Math.PI * 20;
    var JOKE_ROTATE_INTERVAL = 20; // seconds between jokes

    /* ---- 100 one-liner jokes ---- */
    var JOKES = [
        {text: "Why do meeting notes never win arguments? They always get taken out of context.", icon: "📝"},
        {text: "I told my Copilot to take better notes. It said 'I'm doing my best, Dave.'", icon: "🤖"},
        {text: "Meetings: where minutes are kept and hours are lost.", icon: "⏰"},
        {text: "My meeting notes say 'action items TBD.' That was 6 months ago.", icon: "📋"},
        {text: "The best part of this meeting could have been an email.", icon: "📧"},
        {text: "Comparing notes is like comparing apples and autocomplete.", icon: "🍎"},
        {text: "Why did the meeting notes go to therapy? Too many unresolved action items.", icon: "🛋️"},
        {text: "Copilot heard 'let's table that' and started drawing furniture.", icon: "🪑"},
        {text: "I take notes in meetings so I can forget them with documentation.", icon: "🗂️"},
        {text: "This AI is working harder than anyone did in that meeting.", icon: "💪"},
        {text: "Fun fact: 73% of action items are assigned to people not in the room.", icon: "📊"},
        {text: "My notes say 'follow up.' Follow up on what? The world may never know.", icon: "🤷"},
        {text: "The meeting was 60 minutes. The notes are 3 bullet points. Efficiency.", icon: "⚡"},
        {text: "Copilot transcribed 'synergy' 14 times. That's a new record.", icon: "🏆"},
        {text: "Why do executives love meeting minutes? They're the only minutes that matter.", icon: "👔"},
        {text: "This analysis is taking less time than the meeting itself. You're welcome.", icon: "🎁"},
        {text: "Plot twist: the human notes and Copilot notes agree on everything.", icon: "🎬"},
        {text: "If meetings had a Yelp page, the reviews would be... mixed.", icon: "⭐"},
        {text: "Fun fact: the mute button has prevented more conflicts than the UN.", icon: "🔇"},
        {text: "Copilot noted 'someone's dog barked' as a key discussion point.", icon: "🐕"},
        {text: "My meeting notes are just doodles with strategic captions.", icon: "🎨"},
        {text: "The AI is now cross-referencing. Sounds fancier than it is.", icon: "🔬"},
        {text: "If these notes were a movie, it'd be called 'The Usual Suspects.'", icon: "🎥"},
        {text: "Note-taking tip: write 'per our discussion' to sound important.", icon: "💼"},
        {text: "This meeting had 12 attendees and 2 people who actually talked.", icon: "🗣️"},
        {text: "Copilot confused 'Let's circle back' with actual geometry.", icon: "⭕"},
        {text: "Why was the calendar nervous? It had too many dates.", icon: "📅"},
        {text: "Somewhere, a meeting is happening about why there are too many meetings.", icon: "🔄"},
        {text: "The AI is currently judging both sets of notes equally. Very diplomatic.", icon: "⚖️"},
        {text: "These notes have more plot holes than a Netflix original.", icon: "📺"},
        {text: "Interesting: the human caught things the AI missed. Humans 1, Robots 0.", icon: "🏅"},
        {text: "Actually wait, the AI caught things too. Tie game.", icon: "🤝"},
        {text: "Pro tip: 'I'll send a follow-up email' means 'you'll never hear from me.'", icon: "👻"},
        {text: "This AI reads faster than anyone skims meeting recaps.", icon: "📖"},
        {text: "Why did the spreadsheet break up with the meeting notes? No chemistry.", icon: "💔"},
        {text: "Copilot transcribed the awkward silence. Bold move.", icon: "🤐"},
        {text: "If action items were currency, you'd all be billionaires.", icon: "💰"},
        {text: "The AI found a discrepancy. Someone's in trouble.", icon: "🚨"},
        {text: "Just kidding. Discrepancies are totally normal. Probably.", icon: "😅"},
        {text: "Meeting bingo: 'Let's take this offline' — BINGO!", icon: "🎯"},
        {text: "Why don't meeting notes ever go viral? Not enough cat videos.", icon: "🐱"},
        {text: "This analysis uses more brainpower than the meeting used caffeine.", icon: "☕"},
        {text: "Fun fact: 'brief update' in meeting-speak means 45 minutes.", icon: "⏱️"},
        {text: "The AI is consolidating faster than your team consolidates opinions.", icon: "🏃"},
        {text: "Copilot heard 'deep dive' and almost put on scuba gear.", icon: "🤿"},
        {text: "Your notes are in good hands. Robot hands, but still.", icon: "🦾"},
        {text: "Why did the meeting notes fail the exam? They only covered half the material.", icon: "📝"},
        {text: "The AI is scoring your notes. Don't worry, it grades on a curve.", icon: "📈"},
        {text: "Currently comparing notes like a teacher comparing homework answers.", icon: "👩‍🏫"},
        {text: "Meeting rule #1: whoever takes notes controls the narrative.", icon: "👑"},
        {text: "Copilot spelled someone's name wrong. Classic robot move.", icon: "🤦"},
        {text: "Why do meetings always run over? Nobody scheduled a hard stop.", icon: "🛑"},
        {text: "This AI has read both sets of notes. It has opinions now.", icon: "🧠"},
        {text: "The gap analysis found a gap. Who left the door open?", icon: "🚪"},
        {text: "Fun fact: 'Let me push back on that' delays meetings by 15 minutes.", icon: "⏳"},
        {text: "Copilot noted someone said 'great question' without answering it.", icon: "❓"},
        {text: "These meeting minutes are getting the spa treatment. Full QA massage.", icon: "💆"},
        {text: "Why are meeting recaps like horoscopes? Vague but oddly accurate.", icon: "🔮"},
        {text: "The AI is building your executive summary. It's feeling very executive.", icon: "🏢"},
        {text: "If this meeting were a sandwich, the notes are the bread. Mostly air.", icon: "🥖"},
        {text: "Copilot counted 37 uses of 'um.' The human notes were kinder.", icon: "😇"},
        {text: "Current status: teaching an AI to appreciate corporate jargon.", icon: "🎓"},
        {text: "Why did the pen refuse to write meeting notes? It had too many points.", icon: "🖊️"},
        {text: "The AI found an action item no one remembered. Awkward.", icon: "😬"},
        {text: "Meeting notes are proof that we were all there. Allegedly.", icon: "📸"},
        {text: "Copilot transcribed the small talk. Nobody asked for this.", icon: "🗨️"},
        {text: "The consolidation is like couples therapy for your two sets of notes.", icon: "💑"},
        {text: "Fun fact: the average meeting has 3 side conversations happening at once.", icon: "🎭"},
        {text: "This AI doesn't judge. OK, it literally judges. That's the whole point.", icon: "⚖️"},
        {text: "Why do action items reproduce? Nobody follows up to stop them.", icon: "🐰"},
        {text: "The human notes have personality. The Copilot notes have precision.", icon: "🎭"},
        {text: "Somewhere a meeting is starting late. That meeting is everywhere.", icon: "🌍"},
        {text: "Copilot: 'I understood that reference.' Also Copilot: transcribes it wrong.", icon: "🦸"},
        {text: "These notes are getting merged like a perfect Git PR. No conflicts.", icon: "🔀"},
        {text: "Actually there are conflicts. This is more like a real Git PR.", icon: "😂"},
        {text: "The AI is now writing executive-ready minutes. Pinky out.", icon: "🫖"},
        {text: "Meeting hack: nod confidently when you zone out. Works every time.", icon: "😎"},
        {text: "Why was the AI hired? It actually pays attention the whole meeting.", icon: "👂"},
        {text: "Current mood: your notes after a double espresso.", icon: "☕"},
        {text: "The AI has no meetings today. Just this analysis. Living the dream.", icon: "🏖️"},
        {text: "Fun fact: 'parking lot' items are still in the parking lot from Q2 2024.", icon: "🅿️"},
        {text: "Copilot heard 'move the needle' and looked for a sewing kit.", icon: "🧵"},
        {text: "This is the meeting about the meeting notes about the meeting.", icon: "🤯"},
        {text: "The AI is calibrating scores. It's not subjective. It's AI-subjective.", icon: "🎚️"},
        {text: "Why don't meetings have blooper reels? Actually, that would be amazing.", icon: "🎞️"},
        {text: "The executive readiness score measures how much editing you dodged.", icon: "🏋️"},
        {text: "Copilot: great at transcription. Terrible at reading the room.", icon: "🤖"},
        {text: "Almost done! The AI is dotting the i's and crossing the t's.", icon: "✍️"},
        {text: "Your coverage score is coming. Brace yourself.", icon: "🛡️"},
        {text: "Fun fact: no meeting in history has ended with 'that was too short.'", icon: "📏"},
        {text: "The AI is now in 'executive mode.' It's wearing a tiny digital tie.", icon: "👔"},
        {text: "Why did the notes cross the road? To get to the other side conversation.", icon: "🐔"},
        {text: "Hot take: the best meeting is a canceled meeting.", icon: "🔥"},
        {text: "Copilot transcribed background music as 'ambient thought leadership.'", icon: "🎵"},
        {text: "These notes are getting the Hollywood treatment. Coming soon to a PDF near you.", icon: "🎬"},
        {text: "The AI is considering all angles. It has so many angles.", icon: "📐"},
        {text: "Why was the meeting room always cold? Too many frozen decisions.", icon: "🥶"},
        {text: "Patience is a virtue. Especially when waiting for LLMs.", icon: "🧘"},
        {text: "The AI is wrapping up. It's putting a bow on your notes.", icon: "🎀"},
        {text: "Last fun fact: you'll never look at meeting notes the same way again.", icon: "🌟"},
    ];

    document.addEventListener('DOMContentLoaded', function () {
        humanNotes = document.getElementById('humanNotes');
        copilotNotes = document.getElementById('copilotNotes');
        analyzeBtn = document.getElementById('analyzeBtn');
        clearBtn = document.getElementById('clearBtn');
        exportBtn = document.getElementById('exportBtn');
        statusText = document.getElementById('statusText');
        resultsSection = document.getElementById('resultsSection');
        scoreCards = document.getElementById('scoreCards');
        comparisonContent = document.getElementById('comparisonContent');
        minutesContent = document.getElementById('minutesContent');
        scoresDetailContent = document.getElementById('scoresDetailContent');
        humanWordCount = document.getElementById('humanWordCount');
        copilotWordCount = document.getElementById('copilotWordCount');

        // Tracker refs
        trackerEl = document.getElementById('mqTracker');
        trackerStatusEl = document.getElementById('mqTrackerStatus');
        trackerJokeEl = document.getElementById('mqTrackerJoke');

        if (typeof initTheme === 'function') initTheme();

        // Restore drafts from localStorage
        restoreDrafts();

        // Handoff from /recap: if a transcript was stashed in sessionStorage,
        // pre-fill the Copilot Notes textarea with it (one-shot, then cleared).
        var handoff = sessionStorage.getItem('recap_transcript_for_meeting_qa');
        if (handoff) {
            copilotNotes.value = handoff;
            sessionStorage.removeItem('recap_transcript_for_meeting_qa');
        }

        // Wire up input events
        humanNotes.addEventListener('input', onInputChange);
        copilotNotes.addEventListener('input', onInputChange);

        // Cmd/Ctrl+Enter to submit from either textarea
        humanNotes.addEventListener('keydown', handleSubmitShortcut);
        copilotNotes.addEventListener('keydown', handleSubmitShortcut);

        // Initial button state + word counts
        updateButtonState();
        updateWordCount(humanNotes, humanWordCount);
        updateWordCount(copilotNotes, copilotWordCount);

        humanNotes.focus();
    });

    /* ---- Input handling ---- */
    function onInputChange() {
        updateButtonState();
        updateWordCount(humanNotes, humanWordCount);
        updateWordCount(copilotNotes, copilotWordCount);
        saveDrafts();
    }

    function updateButtonState() {
        var hasBoth = humanNotes.value.trim() && copilotNotes.value.trim();
        analyzeBtn.disabled = !hasBoth;
    }

    function handleSubmitShortcut(e) {
        if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') {
            e.preventDefault();
            if (!analyzeBtn.disabled) analyze();
        }
    }

    /* ---- Word count ---- */
    function countWords(text) {
        var trimmed = text.trim();
        if (!trimmed) return 0;
        return trimmed.split(/\s+/).length;
    }

    function updateWordCount(textarea, counter) {
        var wc = countWords(textarea.value);
        counter.textContent = wc + ' word' + (wc !== 1 ? 's' : '');
    }

    /* ---- localStorage persistence ---- */
    function saveDrafts() {
        try {
            localStorage.setItem(STORAGE_KEY, JSON.stringify({
                human: humanNotes.value,
                copilot: copilotNotes.value
            }));
        } catch (_) { /* quota exceeded */ }
    }

    function restoreDrafts() {
        try {
            var saved = JSON.parse(localStorage.getItem(STORAGE_KEY));
            if (saved) {
                if (saved.human) humanNotes.value = saved.human;
                if (saved.copilot) copilotNotes.value = saved.copilot;
            }
        } catch (_) { /* corrupt data */ }
    }

    function clearDrafts() {
        try { localStorage.removeItem(STORAGE_KEY); } catch (_) {}
    }

    /* ================================================================
       PROGRESS TRACKER
       ================================================================ */
    var PHASES = [
        {id: 1, status: 'Preparing and formatting your notes...'},
        {id: 2, status: 'Connecting to AI model...'},
        {id: 3, status: 'Analyzing overlaps, gaps, and discrepancies... (typically ~1 min)'},
        {id: 4, status: 'Building consolidated minutes and scoring...'}
    ];

    function showTracker() {
        trackerEl.style.display = '';
        resultsSection.style.display = 'none';
        trackerStartTime = Date.now();
        trackerJokeIndex = Math.floor(Math.random() * JOKES.length); // random start
        setTrackerPhase(1);
        trackerInterval = setInterval(trackerTick, 1000);
    }

    function hideTracker() {
        trackerEl.style.display = 'none';
        if (trackerInterval) { clearInterval(trackerInterval); trackerInterval = null; }
    }

    function setTrackerPhase(phase) {
        for (var i = 1; i <= 4; i++) {
            var stepEl = document.getElementById('mq-step-' + i);
            var lineEl = document.getElementById('mq-line-' + (i - 1));
            stepEl.className = 'mq-tracker-step';
            if (i < phase) {
                stepEl.classList.add('completed');
                // Replace number with checkmark
                stepEl.querySelector('.mq-tracker-icon').innerHTML =
                    '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="3" stroke-linecap="round"><polyline points="20 6 9 17 4 12"/></svg>';
                if (lineEl) lineEl.className = 'mq-tracker-line completed';
            } else if (i === phase) {
                stepEl.classList.add('active');
                // Show timer ring on analysis step (step 3)
                if (i === 3) {
                    var iconEl = stepEl.querySelector('.mq-tracker-icon');
                    iconEl.classList.add('has-timer');
                    updateTimerRing(iconEl, 0);
                }
            } else {
                // Reset to number
                stepEl.querySelector('.mq-tracker-icon').innerHTML =
                    '<span class="mq-tracker-num">' + i + '</span>';
                stepEl.querySelector('.mq-tracker-icon').classList.remove('has-timer');
            }
        }
        // Update status message
        var phaseObj = PHASES[phase - 1];
        if (phaseObj) trackerStatusEl.textContent = phaseObj.status;
    }

    function setTrackerError() {
        var stepEl = document.getElementById('mq-step-3');
        stepEl.className = 'mq-tracker-step error';
        trackerStatusEl.textContent = 'Analysis failed. You can try again.';
        trackerJokeEl.textContent = '';
        if (trackerInterval) { clearInterval(trackerInterval); trackerInterval = null; }
    }

    function trackerTick() {
        var elapsed = Math.floor((Date.now() - trackerStartTime) / 1000);

        // Update timer ring on step 3 if active
        var step3Icon = document.querySelector('#mq-step-3.active .mq-tracker-icon.has-timer');
        if (step3Icon) updateTimerRing(step3Icon, elapsed);

        // Rotate jokes
        var jokeIdx = Math.floor(elapsed / JOKE_ROTATE_INTERVAL);
        var newIndex = (trackerJokeIndex + jokeIdx) % JOKES.length;
        var joke = JOKES[newIndex];
        var newText = joke.icon + ' ' + joke.text;
        if (trackerJokeEl.textContent !== newText) {
            trackerJokeEl.style.opacity = '0';
            setTimeout(function () {
                trackerJokeEl.textContent = newText;
                trackerJokeEl.style.opacity = '1';
                trackerJokeEl.style.animation = 'none';
                // Trigger reflow
                trackerJokeEl.offsetHeight;
                trackerJokeEl.style.animation = '';
            }, 200);
        }

        // Simulate phase progression (steps 1-2 are fast, step 3 is the long one)
        if (elapsed === 1) setTrackerPhase(2);
        if (elapsed === 3) setTrackerPhase(3);
    }

    function timerRingColor(elapsed) {
        if (elapsed <= 30) return '#10b981';       // green
        if (elapsed <= 60) return '#f59e0b';       // orange
        if (elapsed <= 120) return '#ef4444';      // red
        return '#dc2626';                           // deep red
    }

    function updateTimerRing(iconEl, elapsed) {
        var progress = Math.min(elapsed / EXPECTED_DURATION, 1);
        var dashoffset = RING_CIRCUMFERENCE * (1 - progress);
        var strokeColor = timerRingColor(elapsed);
        var m = Math.floor(elapsed / 60);
        var s = elapsed % 60;
        var timeStr = m + ':' + (s < 10 ? '0' : '') + s;
        iconEl.innerHTML =
            '<div class="mq-tracker-timer-ring">' +
            '<svg viewBox="0 0 44 44"><circle class="ring-bg" cx="22" cy="22" r="20"/>' +
            '<circle class="ring-progress" cx="22" cy="22" r="20" stroke="' + strokeColor + '" stroke-dasharray="' +
            RING_CIRCUMFERENCE.toFixed(1) + '" stroke-dashoffset="' + dashoffset.toFixed(1) + '"/></svg>' +
            '<div class="mq-tracker-timer-text">' + timeStr + '</div></div>';
    }

    function completeTracker() {
        // Mark all steps completed
        setTrackerPhase(5); // beyond 4 = all completed
        // Set all 4 steps to completed
        for (var i = 1; i <= 4; i++) {
            var stepEl = document.getElementById('mq-step-' + i);
            stepEl.className = 'mq-tracker-step completed';
            stepEl.querySelector('.mq-tracker-icon').innerHTML =
                '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="3" stroke-linecap="round"><polyline points="20 6 9 17 4 12"/></svg>';
            stepEl.querySelector('.mq-tracker-icon').classList.remove('has-timer');
            var lineEl = document.getElementById('mq-line-' + i);
            if (lineEl) lineEl.className = 'mq-tracker-line completed';
        }
        var elapsed = Math.round((Date.now() - trackerStartTime) / 1000);
        var m = Math.floor(elapsed / 60);
        var s = elapsed % 60;
        var timeStr = m > 0 ? m + 'm ' + s + 's' : s + 's';
        trackerStatusEl.textContent = 'Analysis complete in ' + timeStr;
        trackerJokeEl.textContent = '';
        if (trackerInterval) { clearInterval(trackerInterval); trackerInterval = null; }
    }

    /* ---- Analyze ---- */
    function analyze() {
        var human = humanNotes.value.trim();
        var copilot = copilotNotes.value.trim();
        if (!human || !copilot) {
            setStatus('⚠️ Please paste both human and Copilot notes.', true);
            return;
        }

        setLoading(true);
        setStatus('');
        showTracker();

        fetch('/api/meeting-qa/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ human_notes: human, copilot_notes: copilot })
        })
        .then(function (r) { return r.json(); })
        .then(function (data) {
            setLoading(false);
            if (!data.success) {
                setTrackerError();
                setTimeout(function () {
                    hideTracker();
                    showError(data.error || 'Analysis failed.');
                }, 2000);
                return;
            }
            completeTracker();
            setStatus('✅ Analysis complete');
            renderResults(data.result);
        })
        .catch(function (err) {
            setLoading(false);
            setTrackerError();
            setTimeout(function () {
                hideTracker();
                showError('Network error: ' + err.message);
            }, 2000);
        });
    }

    /* ---- Render ---- */
    function renderResults(markdown) {
        resultsSection.style.display = 'block';
        exportBtn.style.display = 'inline-flex';

        // Parse scores and show score cards beside the tracker
        var scores = parseScores(markdown);
        renderScoreCards(scores);
        scoreCards.style.display = '';

        // Split markdown into sections
        var sections = splitSections(markdown);
        comparisonContent.innerHTML = renderMd(sections.comparison || '');
        minutesContent.innerHTML = renderMd(sections.minutes || '');
        scoresDetailContent.innerHTML = renderMd(sections.scores || '');

        // Add copy button to consolidated minutes
        addCopyButton('minutesSection', sections.minutes || '');

        // Animate in
        resultsSection.classList.add('mq-fade-in');
        setTimeout(function () { resultsSection.classList.remove('mq-fade-in'); }, 600);

        // Scroll to results
        resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    function splitSections(md) {
        var result = { comparison: '', minutes: '', scores: '' };
        var parts = md.split(/^## /m);
        for (var i = 0; i < parts.length; i++) {
            var p = parts[i];
            var lower = p.toLowerCase();
            if (lower.startsWith('comparison')) {
                result.comparison = p.replace(/^comparison\s*analysis\s*/i, '');
            } else if (lower.startsWith('consolidated')) {
                result.minutes = p.replace(/^consolidated\s*meeting\s*minutes\s*/i, '');
            } else if (lower.startsWith('quality')) {
                result.scores = p.replace(/^quality\s*(scores|assessment)\s*/i, '');
            }
        }
        return result;
    }

    function parseScores(md) {
        var scores = { coverage: 0, accuracy: 0, readiness: 0 };
        var m;
        m = md.match(/coverage\s*score[:\s]*(\d+)\s*\/\s*10/i);
        if (m) scores.coverage = parseInt(m[1], 10);
        m = md.match(/accuracy\s*score[:\s]*(\d+)\s*\/\s*10/i);
        if (m) scores.accuracy = parseInt(m[1], 10);
        m = md.match(/executive\s*readiness\s*score[:\s]*(\d+)\s*\/\s*10/i);
        if (m) scores.readiness = parseInt(m[1], 10);
        return scores;
    }

    function scoreClass(val) {
        if (val >= 8) return 'mq-score-value--high';
        if (val >= 5) return 'mq-score-value--mid';
        return 'mq-score-value--low';
    }

    function renderScoreCards(scores) {
        var cards = [
            { key: 'coverage',  label: '📊 Coverage',           type: 'coverage'  },
            { key: 'accuracy',  label: '🎯 Accuracy',           type: 'accuracy'  },
            { key: 'readiness', label: '📋 Executive Readiness', type: 'readiness' }
        ];
        var html = '';
        for (var i = 0; i < cards.length; i++) {
            var c = cards[i];
            var val = scores[c.key];
            html += '<div class="mq-score-card mq-score-card--' + c.type + '">' +
                '<div class="mq-score-label">' + c.label + '</div>' +
                '<div class="mq-score-value ' + scoreClass(val) + '">' + val +
                '<span class="mq-score-max">/10</span></div>' +
                '<div class="mq-score-bar"><div class="mq-score-bar-fill" style="width:' + (val * 10) + '%"></div></div>' +
                '</div>';
        }
        scoreCards.innerHTML = html;
    }

    function renderMd(text) {
        if (typeof marked !== 'undefined' && marked.parse) {
            return marked.parse(text);
        }
        return '<pre style="white-space:pre-wrap">' + escapeHtml(text) + '</pre>';
    }

    function escapeHtml(s) {
        var d = document.createElement('div');
        d.textContent = s;
        return d.innerHTML;
    }

    /* ---- Copy button for consolidated minutes ---- */
    function addCopyButton(sectionId, rawMarkdown) {
        var section = document.getElementById(sectionId);
        var existing = section.querySelector('.mq-copy-btn');
        if (existing) existing.remove();

        var btn = document.createElement('button');
        btn.className = 'mq-copy-btn';
        btn.innerHTML = '📋 Copy Minutes';
        btn.onclick = function () {
            var minutesEl = document.getElementById('minutesContent');
            var text = minutesEl.innerText || minutesEl.textContent;
            navigator.clipboard.writeText(text).then(function () {
                btn.innerHTML = '✅ Copied!';
                setTimeout(function () { btn.innerHTML = '📋 Copy Minutes'; }, 2000);
            });
        };
        var title = section.querySelector('.mq-result-title');
        if (title) title.appendChild(btn);
    }

    /* ---- Sample data ---- */
    var SAMPLES = [
        {
            human: "Q1 Security Review - March 20, 2026\n\nAttendees: Sarah Chen (CISO), Mike Torres (SOC Lead), Priya Patel (IR Manager), James Wright (VP Eng)\n\nKey Topics:\n- Phishing incidents up 40% this quarter, mostly targeting finance dept\n- New EDR rollout is 85% complete across endpoints\n- Discussed hiring 2 additional SOC analysts for night shift coverage\n- Compliance audit coming in April - need to prep documentation\n- Mike raised concern about alert fatigue - too many false positives from DLP tool\n- Budget approved for new SIEM migration project\n\nAction Items:\n- Priya to send phishing simulation results by Friday\n- Mike to draft SOC analyst job descriptions\n- James to schedule meeting with DLP vendor about tuning\n- Sarah to review compliance checklist before April 5\n\nNext meeting: April 17",
            copilot: "Meeting: Q1 Security Review\nDate: March 20, 2026\nDuration: 58 minutes\nParticipants: Sarah Chen, Mike Torres, Priya Patel, James Wright, Lisa Kumar (joined late)\n\nTopics Discussed:\n\n1. Phishing Trends\n- 40% increase in phishing attempts Q1 vs Q4\n- Finance and HR departments most targeted\n- 3 successful credential harvesting incidents in February\n- Sarah emphasized need for mandatory phishing awareness training refresh\n\n2. EDR Deployment\n- 85% endpoint coverage achieved\n- Remaining 15% are legacy systems requiring exceptions\n- Performance impact reported on older machines (>5 year old hardware)\n- Target: 95% coverage by end of Q2\n\n3. SOC Staffing\n- Current coverage gap on night shift (11pm-7am)\n- Proposal to hire 2 FTEs plus 1 contractor\n- Budget approved from Q2 allocation\n- Mike to have job descriptions ready by March 28\n\n4. DLP Alert Fatigue\n- Current false positive rate: ~62%\n- Vendor meeting requested to discuss tuning options\n- Potential to reduce alerts by 40% with policy adjustments\n- James volunteered to lead vendor engagement\n\n5. Compliance Preparation\n- SOC 2 Type II audit scheduled April 14-18\n- Documentation gap identified in incident response procedures\n- Lisa Kumar assigned to update IR playbooks by April 5\n\n6. SIEM Migration\n- Budget approved: $340K for Sentinel migration\n- Timeline: Q2-Q3 implementation\n- RFP responses due April 1\n\nAction Items:\n- Priya: Deliver phishing simulation report by March 25\n- Mike: SOC analyst job descriptions by March 28\n- James: Schedule DLP vendor call by March 27\n- Sarah: Review compliance checklist by April 5\n- Lisa: Update IR playbooks by April 5\n- Sarah: Send phishing training mandate to all-hands by March 22\n\nNext Meeting: April 17, 2026"
        },
        {
            human: "Product Launch Readiness Check - March 18\n\nPresent: Tom (PM), Rachel (Eng Lead), Kevin (QA), Diana (Marketing)\n\nStatus Update:\n- Backend API is feature complete, load tested to 10K concurrent users\n- Frontend has 3 remaining bugs - 2 critical, 1 minor\n- Marketing landing page ready, email campaign scheduled for April 1\n- Kevin's team found a payment processing edge case that needs fixing\n- Rachel says 2 critical bugs need 3-4 days to fix\n- Tom wants to keep April 7 launch date\n- Discussed rollout strategy - starting with 10% of users\n\nDecisions:\n- Go ahead with April 7 soft launch at 10%\n- Full rollout April 14 if no P0 issues\n\nTODOs:\n- Rachel: Fix critical bugs by March 22\n- Kevin: Full regression test by March 25\n- Diana: Brief support team on known issues\n- Tom: Update stakeholders on timeline",
            copilot: "Meeting: Product Launch Readiness Check\nDate: March 18, 2026\nDuration: 45 minutes\nParticipants: Tom Barrett (PM), Rachel Simmons (Eng Lead), Kevin Cho (QA Lead), Diana Foster (Marketing), Alex Rivera (Support Lead - remote)\n\nAgenda Items:\n\n1. Engineering Status\n- Backend API: feature complete, load tested successfully\n  - Handles 10K concurrent users, p99 latency 230ms\n  - Database connection pooling optimized last week\n- Frontend: 3 open bugs\n  - BUG-4521 (Critical): Payment form loses state on browser back\n  - BUG-4523 (Critical): Accessibility issues on checkout flow (WCAG 2.1 AA)\n  - BUG-4530 (Minor): Tooltip alignment on mobile Safari\n- Rachel estimates 3-4 days for critical bugs, minor bug deprioritized\n\n2. QA Status\n- 94% test coverage on critical paths\n- Payment edge case discovered: duplicate charge when session times out during 3D Secure\n- Kevin requesting 3 additional days for full regression after bug fixes\n\n3. Marketing Readiness\n- Landing page finalized and A/B tested\n- Email campaign scheduled April 1 (42K subscribers)\n- Press embargo lifts April 7\n- Social media content calendar approved\n- Diana noted influencer partnerships confirmed for launch week\n\n4. Support Readiness\n- Alex flagged that support docs are not yet updated\n- FAQ and troubleshooting guide needed before launch\n- Estimated 2 days of work for support documentation\n\n5. Launch Strategy Discussion\n- Phased rollout agreed: 10% → 50% → 100%\n- 10% rollout on April 7 (soft launch)\n- Full rollout April 14 pending no P0/P1 issues\n- Rollback plan documented by Rachel\n\nDecisions:\n1. Proceed with April 7 soft launch (10% traffic)\n2. Full rollout April 14 if no P0 issues in first week\n3. Minor bug (BUG-4530) deferred to post-launch sprint\n4. Support docs must be ready by April 4\n\nAction Items:\n- Rachel: Fix BUG-4521 and BUG-4523 by March 22\n- Rachel: Document rollback procedure by March 24\n- Kevin: Full regression suite by March 25\n- Kevin: Payment edge case retest after fix\n- Diana: Brief support team on known issues by March 26\n- Diana: Prepare launch day social media posts\n- Alex: Complete support docs and FAQ by April 4\n- Tom: Send stakeholder update email by March 19\n- Tom: Schedule launch day war room\n\nRisks:\n- Payment bug fix complexity could delay timeline\n- Support readiness is tight\n\nNext Meeting: March 25 (Go/No-Go decision)"
        }
    ];

    function loadSample() {
        var sample = SAMPLES[Math.floor(Math.random() * SAMPLES.length)];
        humanNotes.value = sample.human;
        copilotNotes.value = sample.copilot;
        onInputChange();
        humanNotes.focus();
        setStatus('🎲 Sample notes loaded — click Analyze to try it out');
    }

    /* ---- Error display ---- */
    function showError(msg) {
        resultsSection.style.display = 'block';
        scoreCards.innerHTML = '';
        comparisonContent.innerHTML = '<div class="mq-error">❌ ' + escapeHtml(msg) + '</div>';
        minutesContent.innerHTML = '';
        scoresDetailContent.innerHTML = '';
        document.getElementById('comparisonSection').style.display = 'block';
        document.getElementById('minutesSection').style.display = 'none';
        document.getElementById('scoresDetailSection').style.display = 'none';
    }

    /* ---- Clear ---- */
    function clear() {
        humanNotes.value = '';
        copilotNotes.value = '';
        resultsSection.style.display = 'none';
        scoreCards.style.display = 'none';
        exportBtn.style.display = 'none';
        hideTracker();
        setStatus('');
        clearDrafts();
        updateButtonState();
        updateWordCount(humanNotes, humanWordCount);
        updateWordCount(copilotNotes, copilotWordCount);
        document.getElementById('comparisonSection').style.display = '';
        document.getElementById('minutesSection').style.display = '';
        document.getElementById('scoresDetailSection').style.display = '';
        humanNotes.focus();
    }

    /* ---- PDF Export ---- */
    function exportPdf() {
        if (typeof DashboardExport === 'undefined') {
            setStatus('⚠️ PDF export library not loaded.');
            return;
        }
        setStatus('📄 Generating PDF…');
        DashboardExport.exportPdf('#resultsSection', {
            title: 'Meeting Minutes QA Report',
            subtitle: 'Generated ' + new Date().toLocaleDateString(),
            sections: ['#scoreCards', '#comparisonSection', '#minutesSection', '#scoresDetailSection']
        }, function () {
            setStatus('✅ PDF exported');
        });
    }

    /* ---- Helpers ---- */
    function setLoading(on) {
        analyzeBtn.disabled = on;
        analyzeBtn.querySelector('.mq-btn-text').style.display = on ? 'none' : '';
        analyzeBtn.querySelector('.mq-btn-spinner').style.display = on ? 'inline-block' : 'none';
    }

    function setStatus(msg, isWarn) {
        statusText.textContent = msg;
        statusText.style.color = isWarn ? '#f59e0b' : '';
    }

    /* ---- Public API ---- */
    window.MeetingQA = {
        analyze: analyze,
        clear: clear,
        exportPdf: exportPdf,
        loadSample: loadSample
    };
})();
