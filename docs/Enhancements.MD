# Meaningful Metrics Dashboard – Enhancement Plan

> Living document tracking UX, visualization, analytics, accessibility, performance, and data model enhancements to implement incrementally.

## 0. Status Key

- [ ] Not Started
- [~] In Progress (partial)
- [x] Complete

---

## 1. Guiding Principles

1. Fast first paint & perceived performance (progressive reveal, skeletons)
2. Accessibility-first (WCAG AA) – keyboard, ARIA, color contrast
3. Analyst efficiency – reduce time to answer core operational questions
4. Consistent theming (light/dark/high-contrast) and color semantics
5. Secure-by-default (CSP-friendly, no inline handlers, sanitize dynamic HTML)
6. Observability of platform itself (latency, data freshness, loads)

---

## 2. Quick Wins (First Pass Targets)

These are low risk, high value and can be shipped independently.

**✅ Recently Completed (2025-09-25):**
- Zebra styling for table rows (improves readability)
- Empty-state messaging for zero results (#10)
- Data freshness timestamp display (#11)
- Table row hover highlighting fixes (dark/light theme)

| #  | Item                                                 | Goal                             | Status |
|----|------------------------------------------------------|----------------------------------|--------|
| 1  | KPI delta % badges                                   | Show change vs previous period   | [ ]    |
| 2  | KPI sparklines                                       | Micro trend context              | [ ]    |
| 3  | Rolling 7‑day avg overlay on timeline                | Smooth noise                     | [ ]    |
| 4  | Pareto chart (Impact)                                | Focus on top causes              | [ ]    |
| 5  | MTTR Control chart                                   | Detect variation / anomalies     | [ ]    |
| 6  | Calendar heatmap (daily volume)                      | Spot seasonal clusters           | [ ]    |
| 7  | MTTR box/violin by severity                          | Display distribution vs averages | [ ]    |
| 8  | Automation adoption trend line                       | Show process maturity            | [ ]    |
| 9  | Column heat shading (MTTR / severity)                | Visual scanning aid              | [ ]    |
| 10 | Empty-state messaging for zero results               | Reduce confusion                 | [x]    |
| 11 | Data freshness timestamp + manual refresh            | Trust & transparency             | [x]    |
| 12 | Toast on anomaly spike (threshold)                   | Real-time awareness              | [ ]    |
| 13 | Colorblind-safe palette toggle                       | Accessibility                    | [ ]    |
| 14 | LocalStorage persistence of filters (full)           | Session continuity               | [ ]    |
| 15 | Delegated filter tag removal (remove inline onclick) | CSP hardening                    | [ ]    |
| 16 | Keyboard shortcuts (/? help overlay)                 | Power use                        | [ ]    |

---

## 3. Visual & Interaction Enhancements

### 3.1 Metric Cards

- Delta vs prior comparable window (absolute & %)
- Sparkline (last 14–30 day mini line) beneath value
- Hover tooltip: definition, formula, sample size (n)
- Click → context filtering (e.g., click Countries → isolate top N in charts)
- Optional audible subtle chime for major improvement regression (respect audio toggle)

### 3.2 Layout & Feedback

- Sticky mini-filter bar (date range + severity toggle) when scrolling
- Compact density toggle (reduced padding; stores preference)
- Progressive skeletons for: KPI cards, table header, first 10 rows
- Animated chart fade-in after data load / filter change

### 3.3 Theming / Personalization

- Accent color picker (persisted)
- Colorblind-safe palette (Okabe–Ito)
- High-contrast variant (increased font weight + distinct outlines)

### 3.4 Microinteractions

- Count-up animation for updated KPI numbers (ease-out, capped <800ms)
- Gentle pulse highlight on KPI whose delta exceeds threshold
- Hover focus states with accessible outline (no reliance on color only)

---

## 4. Advanced Chart / Analytics Additions

| Chart                                         | Purpose                  | Priority | Status |
|-----------------------------------------------|--------------------------|----------|--------|
| Pareto (Impact types)                         | 80/20 insight            | High     | [ ]    |
| Control Chart (MTTR / MTTC)                   | Stability & anomalies    | High     | [ ]    |
| Calendar Heatmap                              | Volume diffusion         | High     | [ ]    |
| Box/Violin MTTR by Severity                   | Distribution shape       | High     | [ ]    |
| Automation Trend Area/Line                    | Process evolution        | High     | [ ]    |
| Created vs Closed + Backlog line              | Flow health              | Med      | [ ]    |
| Cumulative Flow Diagram                       | WIP stability            | Med      | [ ]    |
| Severity Mix Stacked Area                     | Risk composition drift   | Med      | [ ]    |
| Impact Treemap / Sunburst                     | Hierarchical proportions | Med      | [ ]    |
| Hour-of-Day × Day-of-Week Heatmap             | Staffing alignment       | Med      | [ ]    |
| Scatter: Impact vs MTTR (bubble size = count) | Risk vs latency          | Med      | [ ]    |
| Sankey: Source → Type → Impact                | Pipeline path            | Low      | [ ]    |
| Analyst Load Distribution (bar + Gini)        | Workload fairness        | Low      | [ ]    |
| Forecast (ARIMA/Prophet baseline)             | Capacity planning        | Low      | [ ]    |

---

## 5. Insight & Intelligence Layer

| Feature                                         | Description                              | Status |
|-------------------------------------------------|------------------------------------------|--------|
| Anomaly detector (z-score / MAD)                | Flag unusual spikes in volume / MTTR     | [ ]    |
| Insight badges (“Critical MTTR ↓ 18%”)          | Auto-summarized improvements/regressions | [ ]    |
| Outlier spotlight (slowest MTTR cases)          | List top 5 with drill links              | [ ]    |
| Root cause recurrence counter                   | Tracks repeats in window                 | [ ]    |
| Correlation hints (MTTR vs automation adoption) | Simple Pearson/Spearman hints            | [ ]    |
| Annotation layer (policy/tool changes)          | Markers over timeline                    | [ ]    |

---

## 6. Data / API Enhancements

| Enhancement                                                | Rationale                        | Status |
|------------------------------------------------------------|----------------------------------|--------|
| Aggregates endpoint (`/api/meaningful-metrics/aggregates`) | Reduce client computation        | [ ]    |
| Pre-computed rolling metrics (7d/30d)                      | Faster render & consistent math  | [ ]    |
| Provide distributions (arrays or binned) for MTTR/MTTC     | Enable box/violin/control charts | [ ]    |
| Outlier trimming guideline (e.g., P99 cap)                 | Reduce skew on averages          | [ ]    |
| SLA breach metadata (thresholds surfaced)                  | Context clarity                  | [ ]    |
| Data version hash in payload                               | Cache bust & change tracking     | [ ]    |

### Proposed Aggregates JSON Shape

```jsonc
{
  "generated_at": "2025-09-25T14:22:05Z",
  "period_days": 90,
  "kpis": {
    "total": 1234,
    "mttr_mean_secs": 182,
    "mttr_median_secs": 95,
    "mttc_mean_secs": 240,
    "sla_response_breach_pct": 0.07,
    "sla_containment_breach_pct": 0.05
  },
  "time_series": {
    "daily_created": [{"date":"2025-09-01","count":23}, ...],
    "daily_closed": [...],
    "mttr_mean": [...],
    "mttr_median": [...]
  },
  "breakdowns": {
    "impact": [{"impact":"Malicious True Positive","count":112}],
    "severity": [{"severity":4,"count":56}],
    "automation": [{"level":"Automated","count":310}],
    "country_top": [{"country":"US","count":340}],
    "owner_top": [{"owner":"analyst1","count":55}]
  },
  "distributions": {
    "mttr_by_severity": {"4":[210,180,320,...], "3":[...]} 
  },
  "meta": {"data_version":"abc123"}
}
```

---

## 7. Accessibility & Inclusivity

| Item                                          | Goal                        | Status |
|-----------------------------------------------|-----------------------------|--------|
| Associate all sliders w/ `<label for>`        | Screen reader clarity       | [ ]    |
| Add `<caption>` to table                      | Table semantics             | [ ]    |
| Convert filter tags to list semantics         | Structural nav              | [ ]    |
| Keyboard nav for column selector + ESC close  | Operability                 | [ ]    |
| Focus ring visible in both themes             | Usability                   | [ ]    |
| Color contrast audit + dark theme adjustments | WCAG AA                     | [ ]    |
| Provide no-emoji / text-only mode             | Clarity & locale neutrality | [ ]    |

---

## 8. Performance Optimizations

| Item                                            | Approach                 | Status |
|-------------------------------------------------|--------------------------|--------|
| Lazy-load below-the-fold charts                 | IntersectionObserver     | [ ]    |
| Debounce filter application (150–250ms)         | Prevent rapid re-renders | [ ]    |
| Pre-size chart containers to avoid layout shift | CLS reduction            | [ ]    |
| Warm cache for aggregates endpoint              | Edge / CDN friendly      | [ ]    |
| Use `Plotly.react` everywhere (DONE for theme)  | Smooth updates           | [x]    |
| Virtual scroll for table (if >2k rows)          | UI responsiveness        | [ ]    |

---

## 9. Persistence & State

| State Element                          | Current           | Target                                | Status |
|----------------------------------------|-------------------|---------------------------------------|--------|
| Theme                                  | LocalStorage      | ✅ (done)                              | [x]    |
| Column selector open                   | LocalStorage      | ✅ (done)                              | [x]    |
| Filter set                             | Partial (cookies) | Full LocalStorage + export/share link | [ ]    |
| Column order/visibility                | Cookies           | Consolidate to LocalStorage           | [ ]    |
| Last used date range                   | Slider default    | Persist                               | [ ]    |
| Analyst personalization (accent color) | N/A               | LocalStorage                          | [ ]    |

---

## 10. Implementation Phases

### Phase 1 (Foundational UI / Quick Wins)

- KPI deltas & sparklines
- Rolling 7‑day average & Pareto
- Empty states & data freshness
- Colorblind-safe palette toggle

### Phase 2 (Distribution & Stability Insights)

- Control chart (MTTR/MTTC)
- Box/violin severity distributions
- Calendar heatmap
- Automation adoption trend

### Phase 3 (Flow & Risk Evolution)

- Created vs Closed vs Backlog line
- Severity mix stacked area
- Impact treemap/sunburst
- Analyst load distribution

### Phase 4 (Intelligence Layer)

- Anomaly detection & insight badges
- Outlier spotlight & root cause recurrence
- Annotation layer (manual + API-driven)

### Phase 5 (Advanced / Predictive)

- Forecasting
- Correlation explorer
- Sankey flow
- Predictive backlog risk

---

## 11. Definition of Done (Select Items)

**KPI Delta Badges**

- Baseline: previous equal-length period (e.g., last 30 vs prior 30)
- Display: + / - with color (green improvement, red regression; neutral gray ±1%)
- Tooltip: absolute change + relative % + sample sizes

**Pareto Impact Chart**

- Sorted descending bars (Impact count)
- Overlaid cumulative % line with secondary y-axis
- Threshold zone shaded at 80%

**Control Chart (MTTR)**

- Mean line + upper/lower control limits (mean ± 2σ)
- Points beyond limits highlighted (red outline)
- Toggle to switch to MTTC

**Calendar Heatmap**

- 7 columns × N weeks (recent 12–16 weeks)
- Color scale accessible in both themes
- Tooltip: date, count, deviation from rolling avg

**Automation Trend**

- Stacked area or line (Manual / Semi / Auto)
- Option to show % share instead of absolute count

**Box / Violin MTTR by Severity**

- Requires distribution arrays or aggregates
- Outliers plotted; toggle to hide

**Anomaly Detection**

- Simple z-score |z| > 2 or MAD > threshold
- Trigger toast + badge near KPI
- Logged (console + optional /api/events)

---

## 12. Future Stretch Ideas

- Sankey Source → Type → Impact
- Embedding similarity clustering for dedupe
- Root cause NLP clustering (TF-IDF + KMeans)
- Forecast backlog w/ Prophet & overlay confidence band
- Incident narrative generator (“Week summary”)

---

## 13. Metrics to Track Post-Enhancement

| Metric                                       | Baseline Needed | Target            |
|----------------------------------------------|-----------------|-------------------|
| Time to First Filter Interaction             | Capture now     | -15%              |
| KPI Panel Dwell Time                         | Capture         | +10% (engagement) |
| Filter Usage Rate (avg filters/session)      | Capture         | +25%              |
| Dark Mode Adoption %                         | Capture         | >60% opt-in       |
| SLA Breach Investigation Time (proxy clicks) | Manual baseline | -10%              |
| Chart Error Rate (JS errors / sessions)      | Current logs    | <0.5%             |

---

## 14. Engineering Notes

- All new charts MUST register with theme adaptation (reuse `adaptAllChartsTheme`).
- Keep large dataset transformations server-side where viable.
- Introduce a `chartRegistry` object to manage: id, buildFn, dependencies (data slices), and optional transform caches.
- For performance critical loops, pre-index by severity, impact, date buckets.
- Use functional purity for derivations; facilitate simple unit tests.

---

## 15. Open Questions / To Clarify Later

| Question                                               | Notes                                    |
|--------------------------------------------------------|------------------------------------------|
| Should duplicates logic ("Unique") be user-toggleable? | Possibly advanced settings panel         |
| SLA thresholds static or delivered via API?            | Consider embedding in aggregates payload |
| Data retention window expansion needed?                | Maybe support 180d mode later            |
| Multi-tenant / team scoping?                           | Future segmentation feature              |

---

## 16. Change Log

| Date       | Change                              | Author           |
|------------|-------------------------------------|------------------|
| 2025-09-25 | Initial structured enhancement plan | System Assistant |
| 2025-09-25 | Completed: Zebra table styling, empty states, data freshness | System Assistant |

---
*Update this document as features are delivered. Commit early, iterate often.*

