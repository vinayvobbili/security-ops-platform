/* Wiki Knowledge Base — client-side logic */

(function () {
    'use strict';

    // ── Info Modal ────────────────────────────────────────────────────────
    var infoBtn = document.getElementById('wkInfoBtn');
    var infoBackdrop = document.getElementById('wkInfoBackdrop');
    var infoClose = document.getElementById('wkInfoClose');

    if (infoBtn && infoBackdrop) {
        infoBtn.addEventListener('click', function () { infoBackdrop.style.display = 'flex'; });
        infoClose.addEventListener('click', function () { infoBackdrop.style.display = 'none'; });
        infoBackdrop.addEventListener('click', function (e) {
            if (e.target === infoBackdrop) infoBackdrop.style.display = 'none';
        });
    }

    // ── Article rendering (markdown + TOC + backlinks) ──────────────────
    var articleEl = document.getElementById('wkArticle');
    if (articleEl && typeof marked !== 'undefined') {
        var raw = articleEl.textContent;
        var html = marked.parse(raw);

        // Convert [[backlink]] syntax to clickable links
        html = html.replace(/\[\[([^\]|]+?)(?:\|([^\]]+))?\]\]/g, function (_, slug, label) {
            var display = label || slug.replace(/-/g, ' ').replace(/\b\w/g, function (c) { return c.toUpperCase(); });
            var href = '/wiki/' + slug;
            return '<a class="wk-backlink" href="' + href + '">' + display + '</a>';
        });

        articleEl.innerHTML = html;
        buildTOC(articleEl);
    }

    function buildTOC(container) {
        var headings = container.querySelectorAll('h2, h3');
        if (headings.length < 3) return;

        var toc = document.createElement('div');
        toc.className = 'wk-toc';
        toc.innerHTML = '<div class="wk-toc-title">Contents</div>';

        var ol = document.createElement('ol');
        var currentOl = ol;
        var lastLevel = 2;
        var h2Count = 0;

        for (var i = 0; i < headings.length; i++) {
            var h = headings[i];
            var level = parseInt(h.tagName.charAt(1), 10);
            var id = 'section-' + i;
            h.id = id;

            if (level === 2) {
                currentOl = ol;
                lastLevel = 2;
                h2Count++;
            } else if (level === 3 && lastLevel === 2) {
                var subOl = document.createElement('ol');
                if (ol.lastElementChild) {
                    ol.lastElementChild.appendChild(subOl);
                }
                currentOl = subOl;
                lastLevel = 3;
            }

            var li = document.createElement('li');
            var a = document.createElement('a');
            a.href = '#' + id;
            a.textContent = h.textContent;
            li.appendChild(a);
            currentOl.appendChild(li);
        }

        if (h2Count < 2) return;
        toc.appendChild(ol);

        var firstH1 = container.querySelector('h1');
        if (firstH1 && firstH1.nextSibling) {
            var insertBefore = firstH1.nextElementSibling;
            if (insertBefore && insertBefore.tagName === 'P') {
                insertBefore = insertBefore.nextElementSibling;
            }
            if (insertBefore) {
                container.insertBefore(toc, insertBefore);
            } else {
                container.appendChild(toc);
            }
        } else {
            container.insertBefore(toc, container.firstChild);
        }
    }

    // ── Tag filtering (home page) ───────────────────────────────────────
    var tagFilter = document.getElementById('wkTagFilter');
    var cardsGrid = document.getElementById('wkCardsGrid');

    if (tagFilter && cardsGrid) {
        // Check URL for ?tag= parameter
        var urlParams = new URLSearchParams(window.location.search);
        var initialTag = urlParams.get('tag');

        tagFilter.addEventListener('click', function (e) {
            var btn = e.target.closest('.wk-tag-chip');
            if (!btn) return;
            var tag = btn.getAttribute('data-tag');
            applyTagFilter(tag);
            // Update active state
            tagFilter.querySelectorAll('.wk-tag-chip').forEach(function (b) { b.classList.remove('active'); });
            btn.classList.add('active');
        });

        if (initialTag) {
            applyTagFilter(initialTag);
            // Activate the matching chip
            var chip = tagFilter.querySelector('[data-tag="' + CSS.escape(initialTag) + '"]');
            if (chip) {
                tagFilter.querySelector('[data-tag="all"]').classList.remove('active');
                chip.classList.add('active');
            }
        }
    }

    function applyTagFilter(tag) {
        if (!cardsGrid) return;
        var cards = cardsGrid.querySelectorAll('.wk-card');
        cards.forEach(function (card) {
            if (tag === 'all') {
                card.style.display = '';
            } else {
                var cardTags = (card.getAttribute('data-tags') || '').split(',');
                card.style.display = cardTags.indexOf(tag) >= 0 ? '' : 'none';
            }
        });
    }

    // ── Search ──────────────────────────────────────────────────────────
    var searchInput = document.getElementById('wkSearch');
    var homePanel = document.getElementById('wkHomePanel');
    var searchPanel = document.getElementById('wkSearchPanel');
    var searchResults = document.getElementById('wkSearchResults');
    var searchTimer = null;

    if (searchInput) {
        searchInput.addEventListener('input', function () {
            clearTimeout(searchTimer);
            var q = this.value.trim();
            if (!q) {
                hideSearch();
                return;
            }
            searchTimer = setTimeout(function () { doSearch(q); }, 300);
        });
    }

    function hideSearch() {
        if (searchPanel) searchPanel.style.display = 'none';
        if (homePanel) homePanel.style.display = '';
    }

    function doSearch(q) {
        fetch('/api/wiki/search?q=' + encodeURIComponent(q))
            .then(function (r) { return r.json(); })
            .then(function (data) {
                if (homePanel) homePanel.style.display = 'none';
                if (searchPanel) searchPanel.style.display = '';

                if (!data.results || data.results.length === 0) {
                    searchResults.innerHTML = '<div class="wk-empty"><p>No results found for "<strong>' +
                        q.replace(/</g, '&lt;') + '</strong>"</p></div>';
                    return;
                }
                searchResults.innerHTML = data.results.map(function (r) {
                    var tagsHtml = '';
                    if (r.tags && r.tags.length) {
                        tagsHtml = '<div class="wk-result-tags">' + r.tags.slice(0, 4).map(function (t) {
                            return '<span class="wk-card-tag">' + t.split('/').pop() + '</span>';
                        }).join('') + '</div>';
                    }
                    return '<a class="wk-search-result" href="/wiki/' + r.slug + '">' +
                        '<span class="wk-result-title">' + (r.title || r.slug) + '</span>' +
                        tagsHtml +
                        '<span class="wk-result-snippet">' + (r.snippet || '') + '</span></a>';
                }).join('');
            })
            .catch(function () {
                searchResults.innerHTML = '<div class="wk-empty"><p>Search failed. Please try again.</p></div>';
            });
    }

    // ── Graph View ──────────────────────────────────────────────────────
    var graphOverlay = document.getElementById('wkGraphOverlay');
    var graphBtn = document.getElementById('wkGraphBtn');
    var graphClose = document.getElementById('wkGraphClose');
    var graphCanvas = document.getElementById('wkGraphCanvas');
    var graphLegend = document.getElementById('wkGraphLegend');
    var graphData = null;
    var graphAnimId = null;

    var GROUP_COLORS = {
        'category': '#3b82f6',
        'platform': '#10b981',
        'threat-actor': '#ef4444',
        'malware': '#f59e0b',
        'tool': '#8b5cf6',
        'type': '#6b7280',
        'other': '#94a3b8'
    };

    if (graphBtn) {
        graphBtn.addEventListener('click', function () { openGraph(); });
    }
    if (graphClose) {
        graphClose.addEventListener('click', function () { closeGraph(); });
    }
    if (graphOverlay) {
        graphOverlay.addEventListener('click', function (e) {
            if (e.target === graphOverlay) closeGraph();
        });
    }

    function openGraph() {
        graphOverlay.classList.add('active');
        document.body.style.overflow = 'hidden';
        if (!graphData) {
            fetch('/api/wiki/graph')
                .then(function (r) { return r.json(); })
                .then(function (data) {
                    graphData = data;
                    renderGraph(data);
                });
        } else {
            renderGraph(graphData);
        }
    }

    function closeGraph() {
        graphOverlay.classList.remove('active');
        document.body.style.overflow = '';
        if (graphAnimId) {
            cancelAnimationFrame(graphAnimId);
            graphAnimId = null;
        }
    }

    function renderGraph(data) {
        var canvas = graphCanvas;
        var ctx = canvas.getContext('2d');
        var rect = canvas.parentElement.getBoundingClientRect();
        var W = rect.width;
        var H = rect.height - 80;
        canvas.width = W * devicePixelRatio;
        canvas.height = H * devicePixelRatio;
        canvas.style.width = W + 'px';
        canvas.style.height = H + 'px';
        ctx.setTransform(devicePixelRatio, 0, 0, devicePixelRatio, 0, 0);

        var previewEl = document.getElementById('wkGraphPreview');
        var hintEl = document.getElementById('wkGraphHint');

        // Build legend
        var groups = {};
        data.nodes.forEach(function (n) { if (!groups[n.group]) groups[n.group] = true; });
        graphLegend.innerHTML = Object.keys(groups).sort().map(function (g) {
            var color = GROUP_COLORS[g] || GROUP_COLORS['other'];
            return '<span class="wk-legend-item"><span class="wk-legend-dot" style="background:' + color + '"></span>' + g + '</span>';
        }).join('');

        // ── Zoom / pan state ────────────────────────────────────────────
        var zoom = 1, panX = 0, panY = 0;
        var minZoom = 0.3, maxZoom = 4;

        // Convert screen coords → world coords
        function s2w(sx, sy) { return { x: (sx - panX) / zoom, y: (sy - panY) / zoom }; }

        // ── Build nodes ─────────────────────────────────────────────────
        var nodes = data.nodes.map(function (n, i) {
            var angle = (i / data.nodes.length) * Math.PI * 2;
            var r = Math.min(W, H) * 0.42;
            return {
                id: n.id, title: n.title, group: n.group,
                tags: n.tags || [],
                x: W / 2 + Math.cos(angle) * r + (Math.random() - 0.5) * 80,
                y: H / 2 + Math.sin(angle) * r + (Math.random() - 0.5) * 80,
                vx: 0, vy: 0, radius: 6,
                pinned: false
            };
        });

        var nodeMap = {};
        nodes.forEach(function (n) { nodeMap[n.id] = n; });

        var links = data.links.filter(function (l) {
            return nodeMap[l.source] && nodeMap[l.target];
        }).map(function (l) {
            return { source: nodeMap[l.source], target: nodeMap[l.target] };
        });

        // Connection counts for sizing
        var connCount = {};
        links.forEach(function (l) {
            connCount[l.source.id] = (connCount[l.source.id] || 0) + 1;
            connCount[l.target.id] = (connCount[l.target.id] || 0) + 1;
        });
        nodes.forEach(function (n) {
            n.conns = connCount[n.id] || 0;
            n.radius = 5 + Math.min(n.conns * 1.2, 10);
        });

        var linkStrength = Math.min(0.003, 1.5 / (links.length || 1));

        // ── Interaction state ───────────────────────────────────────────
        var hovered = null;
        var selected = null;          // clicked node stays highlighted
        var dragged = null;           // node being dragged
        var panning = false;          // dragging empty space
        var panStartX = 0, panStartY = 0, panStartPX = 0, panStartPY = 0;
        var dragStartX = 0, dragStartY = 0, didDrag = false;
        var iterations = 0, maxIter = 600;

        // ── Physics ─────────────────────────────────────────────────────
        function tick() {
            iterations++;
            var alpha = Math.max(0.005, 1 - iterations / maxIter) * 0.4;

            for (var i = 0; i < nodes.length; i++) {
                for (var j = i + 1; j < nodes.length; j++) {
                    var dx = nodes[j].x - nodes[i].x;
                    var dy = nodes[j].y - nodes[i].y;
                    var dist = Math.sqrt(dx * dx + dy * dy) || 1;
                    if (dist < 60) dist = 60;
                    var force = 12000 / (dist * dist);
                    var fx = dx / dist * force * alpha;
                    var fy = dy / dist * force * alpha;
                    nodes[i].vx -= fx; nodes[i].vy -= fy;
                    nodes[j].vx += fx; nodes[j].vy += fy;
                }
            }

            links.forEach(function (l) {
                var dx = l.target.x - l.source.x;
                var dy = l.target.y - l.source.y;
                var dist = Math.sqrt(dx * dx + dy * dy) || 1;
                var force = (dist - 200) * linkStrength * alpha;
                var fx = dx / dist * force;
                var fy = dy / dist * force;
                l.source.vx += fx; l.source.vy += fy;
                l.target.vx -= fx; l.target.vy -= fy;
            });

            nodes.forEach(function (n) {
                n.vx += (W / 2 - n.x) * 0.0003 * alpha;
                n.vy += (H / 2 - n.y) * 0.0003 * alpha;
            });

            nodes.forEach(function (n) {
                if (n === dragged || n.pinned) return;
                n.vx *= 0.75; n.vy *= 0.75;
                n.x += n.vx; n.y += n.vy;
            });
        }

        // ── Drawing ─────────────────────────────────────────────────────
        function truncate(str, max) {
            return str.length > max ? str.substring(0, max - 1) + '\u2026' : str;
        }

        function draw() {
            ctx.save();
            ctx.setTransform(devicePixelRatio, 0, 0, devicePixelRatio, 0, 0);
            ctx.clearRect(0, 0, W, H);
            ctx.translate(panX, panY);
            ctx.scale(zoom, zoom);

            var labelFont = (10 / zoom) + 'px -apple-system, BlinkMacSystemFont, sans-serif';
            var hoverFont = 'bold ' + (13 / zoom) + 'px -apple-system, BlinkMacSystemFont, sans-serif';
            var pinFont = 'bold ' + (8 / zoom) + 'px -apple-system, BlinkMacSystemFont, sans-serif';

            // The "focus" node is whichever is hovered, else whichever is selected
            var focus = hovered || selected;

            // Links
            links.forEach(function (l) {
                var isHighlighted = focus && (l.source === focus || l.target === focus);
                ctx.strokeStyle = isHighlighted ? 'rgba(59,130,246,0.6)' : 'rgba(148,163,184,0.15)';
                ctx.lineWidth = (isHighlighted ? 2 : 1) / zoom;
                ctx.beginPath();
                ctx.moveTo(l.source.x, l.source.y);
                ctx.lineTo(l.target.x, l.target.y);
                ctx.stroke();
            });

            // Nodes + labels
            nodes.forEach(function (n) {
                var color = GROUP_COLORS[n.group] || GROUP_COLORS['other'];
                var isFocused = n === focus;
                var isConnected = false;
                if (focus && !isFocused) {
                    isConnected = links.some(function (l) {
                        return (l.source === focus && l.target === n) || (l.target === focus && l.source === n);
                    });
                }
                var dimmed = focus && !isFocused && !isConnected;

                // Circle
                ctx.beginPath();
                ctx.arc(n.x, n.y, n.radius, 0, Math.PI * 2);
                ctx.fillStyle = dimmed ? 'rgba(148,163,184,0.12)' : color;
                ctx.fill();

                // Pinned ring
                if (n.pinned) {
                    ctx.strokeStyle = '#f59e0b';
                    ctx.lineWidth = 2 / zoom;
                    ctx.stroke();
                }
                if (isFocused) {
                    ctx.strokeStyle = '#fff';
                    ctx.lineWidth = 2.5 / zoom;
                    ctx.stroke();
                }
                // Selected ring (when not also hovered)
                if (n === selected && n !== hovered) {
                    ctx.strokeStyle = 'rgba(59,130,246,0.7)';
                    ctx.lineWidth = 2 / zoom;
                    ctx.beginPath();
                    ctx.arc(n.x, n.y, n.radius + 4 / zoom, 0, Math.PI * 2);
                    ctx.stroke();
                }

                // Label
                ctx.textAlign = 'center';
                if (dimmed) {
                    ctx.font = labelFont;
                    ctx.fillStyle = 'rgba(148,163,184,0.15)';
                    ctx.fillText(truncate(n.title, 18), n.x, n.y + n.radius + 12 / zoom);
                } else {
                    ctx.font = isFocused ? hoverFont : labelFont;
                    ctx.fillStyle = isFocused ? '#f1f5f9' : 'rgba(226,232,240,0.7)';
                    ctx.fillText(truncate(n.title, isFocused ? 40 : 22), n.x, n.y + n.radius + 12 / zoom);
                }

                // Pin indicator
                if (n.pinned && !dimmed) {
                    ctx.font = pinFont;
                    ctx.fillStyle = '#f59e0b';
                    ctx.fillText('\u{1F4CC}', n.x + n.radius + 3 / zoom, n.y - n.radius);
                }
            });

            ctx.restore();
        }

        // ── Animation loop ──────────────────────────────────────────────
        var needsRedraw = false;

        function animate() {
            tick();
            draw();
            if (iterations < maxIter || dragged || hovered || selected || needsRedraw) {
                needsRedraw = false;
                graphAnimId = requestAnimationFrame(animate);
            }
        }

        function ensureRunning() {
            if (!graphAnimId) animate();
        }

        // ── Hit testing (world coords) ──────────────────────────────────
        function getNodeAt(wx, wy) {
            for (var i = nodes.length - 1; i >= 0; i--) {
                var n = nodes[i];
                var dx = wx - n.x, dy = wy - n.y;
                var hitR = n.radius + 4 / zoom;
                if (dx * dx + dy * dy <= hitR * hitR) return n;
            }
            return null;
        }

        // ── Preview card ────────────────────────────────────────────────
        function showPreview(n, screenX, screenY) {
            var gpTitle = document.getElementById('wkGpTitle');
            var gpTags = document.getElementById('wkGpTags');
            var gpStats = document.getElementById('wkGpStats');

            gpTitle.textContent = n.title;
            gpTags.innerHTML = n.tags.slice(0, 6).map(function (t) {
                var g = t.indexOf('/') >= 0 ? t.split('/')[0] : 'type';
                return '<span class="wk-gp-tag" data-g="' + g + '">' + t + '</span>';
            }).join('');
            gpStats.innerHTML = '<strong>' + n.conns + '</strong> connections' +
                (n.pinned ? ' &middot; <strong style="color:#f59e0b">pinned</strong>' : '');

            // Position near cursor but keep on screen
            var pw = 280, ph = previewEl.offsetHeight || 100;
            var px = screenX + 16;
            var py = screenY - ph / 2;
            if (px + pw > W - 8) px = screenX - pw - 16;
            if (py < 8) py = 8;
            if (py + ph > H - 8) py = H - ph - 8;

            previewEl.style.left = px + 'px';
            previewEl.style.top = (py + 80) + 'px'; // offset for header+legend
            previewEl.style.display = '';
        }

        function hidePreview() {
            previewEl.style.display = 'none';
        }

        // ── Mouse: move ─────────────────────────────────────────────────
        canvas.addEventListener('mousemove', function (e) {
            var br = canvas.getBoundingClientRect();
            var sx = e.clientX - br.left;
            var sy = e.clientY - br.top;

            // Panning
            if (panning) {
                var pdx = sx - panStartX, pdy = sy - panStartY;
                if (pdx * pdx + pdy * pdy > 9) didDrag = true;
                panX = panStartPX + pdx;
                panY = panStartPY + pdy;
                needsRedraw = true;
                ensureRunning();
                hidePreview();
                return;
            }

            var w = s2w(sx, sy);

            // Dragging a node
            if (dragged) {
                var dx = sx - dragStartX, dy = sy - dragStartY;
                if (dx * dx + dy * dy > 9) didDrag = true;
                dragged.x = w.x;
                dragged.y = w.y;
                dragged.vx = 0;
                dragged.vy = 0;
                hidePreview();
                ensureRunning();
                return;
            }

            var node = getNodeAt(w.x, w.y);
            if (node !== hovered) {
                hovered = node;
                canvas.style.cursor = node ? 'grab' : 'default';
                if (node) {
                    showPreview(node, sx, sy);
                } else if (!selected) {
                    hidePreview();
                }
                ensureRunning();
            } else if (node) {
                showPreview(node, sx, sy);
            }
        });

        // ── Mouse: down ─────────────────────────────────────────────────
        canvas.addEventListener('mousedown', function (e) {
            var br = canvas.getBoundingClientRect();
            var sx = e.clientX - br.left;
            var sy = e.clientY - br.top;
            var w = s2w(sx, sy);
            var node = getNodeAt(w.x, w.y);

            if (node) {
                dragged = node;
                dragStartX = sx;
                dragStartY = sy;
                didDrag = false;
                canvas.style.cursor = 'grabbing';
            } else {
                // Pan
                panning = true;
                panStartX = sx;
                panStartY = sy;
                panStartPX = panX;
                panStartPY = panY;
                didDrag = false;
                canvas.style.cursor = 'move';
            }
            hidePreview();
        });

        // ── Mouse: up ───────────────────────────────────────────────────
        canvas.addEventListener('mouseup', function (e) {
            if (dragged) {
                if (didDrag) {
                    // Pin the node where the user dropped it
                    dragged.pinned = true;
                    dragged.vx = 0;
                    dragged.vy = 0;
                } else {
                    // Single click without drag → open article
                    window.location.href = '/wiki/' + dragged.id;
                }
                dragged = null;
            }
            panning = false;
            canvas.style.cursor = hovered ? 'grab' : 'default';
            needsRedraw = true;
            ensureRunning();
        });

        // ── Mouse: right-click → unpin ──────────────────────────────────
        canvas.addEventListener('contextmenu', function (e) {
            var br = canvas.getBoundingClientRect();
            var w = s2w(e.clientX - br.left, e.clientY - br.top);
            var node = getNodeAt(w.x, w.y);
            if (node && node.pinned) {
                e.preventDefault();
                node.pinned = false;
                needsRedraw = true;
                ensureRunning();
            }
        });

        // ── Mouse: wheel → zoom ─────────────────────────────────────────
        canvas.addEventListener('wheel', function (e) {
            e.preventDefault();
            var br = canvas.getBoundingClientRect();
            var sx = e.clientX - br.left;
            var sy = e.clientY - br.top;

            var factor = e.deltaY < 0 ? 1.12 : 1 / 1.12;
            var newZoom = Math.max(minZoom, Math.min(maxZoom, zoom * factor));

            // Zoom toward cursor position
            panX = sx - (sx - panX) * (newZoom / zoom);
            panY = sy - (sy - panY) * (newZoom / zoom);
            zoom = newZoom;

            needsRedraw = true;
            ensureRunning();
            hidePreview();
        }, { passive: false });

        // ── Mouse: leave ────────────────────────────────────────────────
        canvas.addEventListener('mouseleave', function () {
            hovered = null;
            dragged = null;
            panning = false;
            canvas.style.cursor = 'default';
            hidePreview();
        });

        // ── Control buttons ──────────────────────────────────────────────
        function applyZoom(factor) {
            var newZoom = Math.max(minZoom, Math.min(maxZoom, zoom * factor));
            // Zoom toward center of canvas
            var cx = W / 2, cy = H / 2;
            panX = cx - (cx - panX) * (newZoom / zoom);
            panY = cy - (cy - panY) * (newZoom / zoom);
            zoom = newZoom;
            needsRedraw = true;
            ensureRunning();
        }

        function applyPan(dx, dy) {
            panX += dx;
            panY += dy;
            needsRedraw = true;
            ensureRunning();
        }

        var btnZoomIn = document.getElementById('wkZoomIn');
        var btnZoomOut = document.getElementById('wkZoomOut');
        var btnPanUp = document.getElementById('wkPanUp');
        var btnPanDown = document.getElementById('wkPanDown');
        var btnPanLeft = document.getElementById('wkPanLeft');
        var btnPanRight = document.getElementById('wkPanRight');
        var btnReset = document.getElementById('wkResetView');

        if (btnZoomIn) btnZoomIn.addEventListener('click', function () { applyZoom(1.3); });
        if (btnZoomOut) btnZoomOut.addEventListener('click', function () { applyZoom(1 / 1.3); });
        if (btnPanUp) btnPanUp.addEventListener('click', function () { applyPan(0, 80); });
        if (btnPanDown) btnPanDown.addEventListener('click', function () { applyPan(0, -80); });
        if (btnPanLeft) btnPanLeft.addEventListener('click', function () { applyPan(80, 0); });
        if (btnPanRight) btnPanRight.addEventListener('click', function () { applyPan(-80, 0); });
        if (btnReset) btnReset.addEventListener('click', function () {
            zoom = 1; panX = 0; panY = 0;
            selected = null;
            hidePreview();
            needsRedraw = true;
            ensureRunning();
        });

        // Fade out hint after 5s
        if (hintEl) {
            setTimeout(function () {
                hintEl.style.transition = 'opacity 1.5s';
                hintEl.style.opacity = '0';
                setTimeout(function () { hintEl.style.display = 'none'; }, 1500);
            }, 5000);
        }

        iterations = 0;
        animate();
    }

    // ── Compile status polling ──────────────────────────────────────────
    var pollInterval = null;

    function pollStatus() {
        fetch('/api/wiki/status')
            .then(function (r) { return r.json(); })
            .then(function (data) {
                var banner = document.getElementById('wkCompileBanner');
                if (data.running) {
                    banner.classList.add('active');
                } else {
                    banner.classList.remove('active');
                    if (pollInterval) {
                        clearInterval(pollInterval);
                        pollInterval = null;
                    }
                    if (data.last_result) {
                        var msg = data.last_result.error
                            ? 'Compile failed: ' + data.last_result.error
                            : 'Compiled ' + (data.last_result.compiled || 0) + ' articles';
                        showToast(msg);
                        if (data.last_result.compiled > 0) {
                            setTimeout(function () { location.reload(); }, 1500);
                        }
                    }
                    if (data.stats) {
                        var el;
                        el = document.getElementById('wkArticleCount');
                        if (el) el.textContent = data.stats.article_count || 0;
                        el = document.getElementById('wkTagCount');
                        if (el) el.textContent = data.stats.tag_count || 0;
                        el = document.getElementById('wkTotalSize');
                        if (el) el.textContent = data.stats.total_size_str || '0 KB';
                    }
                }
            });
    }

    window.triggerCompile = function (full) {
        var pw = prompt('Enter edit password:');
        if (!pw) return;

        fetch('/api/wiki/compile', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ full: !!full, password: pw })
        })
        .then(function (r) { return r.json(); })
        .then(function (data) {
            if (data.success) {
                showToast(data.message);
                var banner = document.getElementById('wkCompileBanner');
                var msg = document.getElementById('wkCompileMsg');
                msg.textContent = full ? 'Recompiling all articles...' : 'Compiling new articles...';
                banner.classList.add('active');
                if (!pollInterval) {
                    pollInterval = setInterval(pollStatus, 3000);
                }
            } else {
                showToast(data.error || 'Compile failed');
            }
        })
        .catch(function () { showToast('Request failed'); });
    };

    function showToast(msg) {
        var toast = document.getElementById('wkToast');
        toast.textContent = msg;
        toast.classList.add('show');
        setTimeout(function () { toast.classList.remove('show'); }, 3500);
    }

    pollStatus();
})();
