b# Security Audit Report - Repository Public Release Readiness

**Generated:** 2025-12-15
**Status:** 🔴 NOT READY - Sanitization in progress
**Audited Files:** 70+ files containing sensitive references

---

## Executive Summary

This repository requires significant sanitization before public release on GitHub. The codebase contains extensive company-specific references, internal infrastructure details, and personal information that must be removed or genericized.

---

## Critical Issues Found

### 1. Email Addresses (Priority: CRITICAL)
**Status:** ⏳ Pending

**Occurrences:** 50+ instances across codebase

**Affected Files:**
- `.env` - Personal and team email addresses (lines 55-61)
- `services/send-email.py` - Hardcoded test emails
- `web/templates/employee_reach_out_form.html`
- `web/templates/employee_reach_out_already_completed.html`
- `email_templates/employee_reach_out.html`
- `web/static/js/employee_reach_out.js`
- `web/static/js/toodles_chat.js`
- `web/static/js/metrics/charts.js`
- `src/components/abandoned_tickets.py`
- `src/components/ticket_cache.py`
- `src/charts/aging_tickets.py`
- `web/templates/toodles_chat.html`
- `web/templates/red_team_testing_form.html`

**Action Required:**
- Replace `@company.com` → `@example.com`
- Replace `security@company.com` → `security@company.com`
- Replace personal emails with generic placeholders

---

### 2. Internal Infrastructure URLs (Priority: CRITICAL)
**Status:** ⏳ Pending

**Internal Domains Found:**
- `metcirt-lab-12.internal.company.com` (20+ occurrences)
- `lab-vm-12.internal.company.com`
- `gdnr.company.com`
- `api.company.com`
- `tanium.company.com`
- `infoblox.company.com`
- `onprem.tanium.company.com`

**Affected Files:**
- `deployment/log-viewer-index.html` - All service URLs
- `web/templates/burger_menu.html` - Log viewer link
- `xsoar_scripts/SetEmployeeReachOutCountdownTimer.py`
- `email_templates/employee_reach_out.html`
- `services/service_now.py`
- `services/tanium.py`
- `deployment/setup_log_viewers.sh`
- `deployment/nginx-log-viewer.conf`
- `docs/https_conversion_plan.md`
- `docs/COUNTDOWN_TIMER_INTEGRATION.md`
- `webex_bots/toodles.py`
- `web/templates/red_team_testing_form.html`
- `.env` (lines 69-71)

**Action Required:**
- Replace internal URLs with placeholders
- Use environment variables for configurable endpoints

---

### 3. Personal Information (Priority: CRITICAL)
**Status:** ⏳ Pending

**Personal File Paths:**
- `/Users/user@company.com/PycharmProjects/IR` (15+ occurrences)

**Affected Files:**
- `src/pokedex/EXTEND_TO_OTHER_BOTS.md`
- `src/pokedex/start_sleep_monitor.sh`
- `src/pokedex/pokedex_zscaler_monitor.sh`
- `src/pokedex/manage_pokedex_zscaler.sh`
- `src/pokedex/soc-bot-preloader.service`
- `src/pokedex/zscaler_bot_monitor.sh`
- `src/pokedex/run_pokedex.sh`
- `.env` (line 29, 110-111)

**Personal Names/Info in .env:**
- `MY_NAME="Vinay Vobbilichetty"` (line 58)
- `MY_EMAIL_ADDRESS` (line 59)
- `MY_WHATSAPP_NUMBER` (line 64)
- `WHATSAPP_RECEIVER_NUMBERS` (line 65)

**Action Required:**
- Replace with generic paths: `/home/user/projects/IR`
- Replace personal info with placeholders
- Use environment variables

---

### 4. Company Name References (Priority: HIGH)
**Status:** ⏳ Pending

**"Acme" References:** 200+ occurrences across 70+ files

**Categories:**
1. **Comments/Docstrings:**
   - `my_bot/core/my_model.py:20` - "Created for Acme Security Operations"

2. **CSS/Branding:**
   - `web/static/css/slide-show.css` - Acme brand colors
   - `web/static/css/apt_other_names_results.css` - Acme variables
   - `web/static/css/red_team_testing_form.css`
   - `web/static/css/msoc.css`
   - `web/static/css/employee_reach_out.css`
   - `web/static/css/ticket_import.css`
   - `web/static/css/upcoming_travel_notification_form.css`
   - `email_templates/employee_reach_out.html` - Branding and copyright

3. **Code Logic:**
   - `src/components/ticket_cache.py` - Remove @company.com domain
   - `src/components/abandoned_tickets.py` - Email domain stripping
   - `src/charts/aging_tickets.py` - Email processing
   - `src/charts/vectra_volume.py` - Acme branding in charts
   - `web/static/js/metrics/charts.js` - Email processing
   - `web/static/js/toodles_chat.js` - Email construction

4. **Service Names:**
   - `com.acme.soc-bot-preloader` - LaunchAgent name (5+ files)

**Action Required:**
- Replace "Acme" → "Company"
- Replace company-specific service names
- Genericize branding

---

### 5. Team/Organization Names (Priority: HIGH)
**Status:** ⏳ Pending

**"METCIRT" References:** 100+ occurrences

**Affected Files:**
- `src/components/*.py` - Ticket type filtering
- `webex_bots/*.py` - Bot configurations
- `xsoar_scripts/*.py` - XSOAR list names
- `data/data_maps.py` - Team mappings
- `.env` - TEAM_NAME configuration
- `deployment/log-viewer-index.html`
- Multiple deployment scripts

**Azure DevOps References:**
- `Acme-Cyber-Security`
- `Acme-US`
- `Acme-Cyber-Platforms`
- `Acme-US-2`

**Action Required:**
- Replace "METCIRT" → "SIRT" or "SOC-TEAM"
- Genericize Azure DevOps organization names

---

### 6. ServiceNow Configuration (Priority: HIGH)
**Status:** ⏳ Pending

**Company-Specific Endpoints:**
- `services/service_now.py:300-301` - Custom Acme ServiceNow API endpoint
- `.env:43` - SNOW_BASE_URL with api.company.com

**Action Required:**
- Replace with generic placeholders
- Document required endpoint format

---

### 7. Geographic/Regional References (Priority: MEDIUM)
**Status:** ⏳ Pending

**Affected Files:**
- `data/regions_by_country.json:34` - "Malaysia - AMAcme": "APAC"

**Action Required:**
- Remove company name from region mapping

---

### 8. Test/Demo Credentials (Priority: LOW)
**Status:** ⏳ Pending

**Credentials in Code:**
- `deployment/log_viewer.py` - Username: `metcirt`, Password: `metcirt`
- `deployment/install_systemd_services.sh` - Echo credentials
- `deployment/setup_log_viewers.sh` - htpasswd setup with metcirt credentials

**Action Required:**
- Replace with generic demo credentials

---

### 9. Hostnames in Test Data (Priority: MEDIUM)
**Status:** ⏳ Pending

**Test Hostnames:**
- `services/tanium.py:710` - Commented test hostname `TEST-HOST-002.INTERNAL`
- `services/tanium.py:747-748` - Test data with `TEST-HOST-001.INTERNAL` and `TEST-HOST-002.INTERNAL`
- `services/service_now.py:507` - Test hostname `USHZK3C64.internal.company.com`

**Action Required:**
- Replace with generic test hostnames

---

## Good Security Practices Found ✅

1. `.env` file properly excluded via `.gitignore`
2. No `.env` file in git history
3. SSL certificates excluded from git
4. Sample `.env.sample` file provided without real credentials
5. Virtual environment (.venv) excluded
6. Secrets referenced via environment variables (not hardcoded)

---

## Remediation Progress

### Phase 1: Critical Cleanup ⏳ IN PROGRESS

- [ ] **Task 1.1:** Replace all email addresses
- [ ] **Task 1.2:** Sanitize internal infrastructure URLs
- [ ] **Task 1.3:** Remove personal file paths
- [ ] **Task 1.4:** Replace company name references
- [ ] **Task 1.5:** Genericize team/organization names

### Phase 2: Configuration Sanitization 🔜 PENDING

- [ ] **Task 2.1:** Update ServiceNow configurations
- [ ] **Task 2.2:** Sanitize Azure DevOps references
- [ ] **Task 2.3:** Replace test credentials
- [ ] **Task 2.4:** Clean up test hostnames

### Phase 3: Documentation Updates 🔜 PENDING

- [ ] **Task 3.1:** Update README.md
- [ ] **Task 3.2:** Create SECURITY.md
- [ ] **Task 3.3:** Update .env.sample
- [ ] **Task 3.4:** Add setup documentation

### Phase 4: Final Verification 🔜 PENDING

- [ ] **Task 4.1:** Full codebase scan for missed references
- [ ] **Task 4.2:** Verify no secrets in git history
- [ ] **Task 4.3:** Test with fresh clone
- [ ] **Task 4.4:** Final security review

---

## Files Requiring Immediate Attention

**Top 20 Files (by severity):**
1. `.env` - Contains multiple sensitive references
2. `email_templates/employee_reach_out.html` - Company branding
3. `services/service_now.py` - Internal endpoints
4. `services/tanium.py` - Internal URLs and hostnames
5. `data/data_maps.py` - Organization structure
6. `deployment/log-viewer-index.html` - All internal URLs
7. `web/templates/burger_menu.html` - Internal links
8. `web/templates/employee_reach_out_form.html` - Branding
9. `web/templates/red_team_testing_form.html` - Internal URLs
10. `xsoar_scripts/SetEmployeeReachOutCountdownTimer.py` - Internal URL
11. `src/pokedex/` - All shell scripts (personal paths)
12. `my_config.py` - Configuration structure
13. `web/static/css/slide-show.css` - Branding
14. `web/static/css/employee_reach_out.css` - Branding
15. `web/static/js/toodles_chat.js` - Email handling
16. `webex_bots/toodles.py` - Internal URLs
17. `src/components/ticket_cache.py` - Email processing
18. `src/charts/*.py` - Multiple files with company references
19. `services/send-email.py` - Test emails
20. `deployment/setup_log_viewers.sh` - Internal URLs and credentials

---

## Change Log

### 2025-12-15
- Initial security audit completed
- Report generated
- 70+ files identified with sensitive content
- Remediation plan created
- **Status:** Starting sanitization process

---

## Next Steps

1. ✅ Create this report
2. ⏳ Start systematic sanitization (in progress)
3. 🔜 Update report after each major change
4. 🔜 Final verification scan
5. 🔜 Create sanitized public repository

---

**Last Updated:** 2025-12-15 (Report Created)
**Next Review:** After Phase 1 completion