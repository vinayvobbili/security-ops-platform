# /src/utils/bot_messages.py
"""
Bot engagement messages for user interaction
"""

# Security awareness tips for user engagement (displayed during processing)
THINKING_MESSAGES = [
    # Password Security
    "🔐 Security tip: Rotate your passwords every 90 days!",
    "🔑 Remember: Never reuse the same password across multiple accounts!",
    "🛡️ Pro tip: Use a passphrase instead of a password - longer and easier to remember!",
    "🔐 Always use a password manager to generate and store unique passwords!",
    "🔑 Security reminder: Your password should be at least 16 characters long!",

    # Phishing & Email Security
    "📧 Never click links from unknown senders - always verify first!",
    "🎣 Phishing tip: Hover over links to see the real destination before clicking!",
    "📨 Suspicious email? When in doubt, report it to the security team!",
    "🚨 Check the sender's email address carefully - attackers use look-alike domains!",
    "📧 Never share sensitive information via email - it's not secure!",
    "🎣 Real companies never ask for passwords via email - it's always a scam!",

    # Multi-Factor Authentication
    "🔐 Always enable MFA on all your accounts - it blocks 99% of attacks!",
    "📱 Use authenticator apps instead of SMS for better MFA security!",
    "🛡️ MFA fatigue attacks are real - never approve unexpected MFA prompts!",
    "🔑 Treat your MFA backup codes like passwords - store them securely!",

    # Software Updates & Patching
    "⚡ Keep your software updated - most breaches exploit known vulnerabilities!",
    "🔄 Enable automatic updates whenever possible - don't delay patches!",
    "💻 Outdated software is the #1 entry point for attackers - update regularly!",
    "🛡️ Your endpoint protection is only effective if it's up to date!",

    # Endpoint Security
    "💻 Never disable your antivirus or EDR - they're your first line of defense!",
    "🔒 Lock your workstation when stepping away - every single time!",
    "🖥️ Keep sensitive data off your local machine - use approved cloud storage!",
    "🛡️ Only install software from approved sources - malware loves unofficial downloads!",

    # Network Security
    "📡 Public WiFi is dangerous - always use VPN when working remotely!",
    "🌐 Never access sensitive systems over unsecured networks!",
    "🔐 VPN protects your data in transit - use it for all remote work!",
    "📱 Your home network should be secured with WPA3 encryption!",

    # Social Engineering Awareness
    "🎭 Social engineering is the #1 attack method - trust your instincts!",
    "🚨 If something feels urgent and unusual, it's probably a scam!",
    "📞 Never share verification codes over the phone - even if they claim to be IT!",
    "🎣 Attackers impersonate executives - verify requests through separate channels!",
    "💬 Be skeptical of unexpected messages asking you to take immediate action!",

    # Data Protection
    "🗄️ Encrypt sensitive data at rest and in transit - always!",
    "📊 Follow the principle of least privilege - only access what you need!",
    "🔒 Don't share credentials - even with coworkers or contractors!",
    "💾 Sensitive data should never leave approved systems!",

    # Backup & Recovery
    "💾 Regular backups saved countless organizations from ransomware!",
    "🔄 Test your backups regularly - you don't want surprises during recovery!",
    "📦 Follow the 3-2-1 backup rule: 3 copies, 2 media types, 1 offsite!",

    # Physical Security
    "🚪 Don't hold doors open for people you don't recognize - report tailgating!",
    "🏢 Physical access = digital access - keep facilities secure!",
    "📱 Never leave devices unattended in public spaces!",
    "🔐 Shred documents containing sensitive information!",

    # Incident Response
    "🚨 Spot something suspicious? Report it immediately - don't wait!",
    "⚡ Speed matters in incident response - early detection saves millions!",
    "🛡️ If you think you clicked a phishing link, report it NOW!",
    "📞 Know your incident response contacts - save them in your phone!",

    # Browser Security
    "🌐 Clear your browser cache and cookies regularly!",
    "🔒 Look for HTTPS before entering any credentials!",
    "🚫 Don't save passwords in your browser - use a password manager instead!",
    "🔐 Use separate browsers for work and personal activities!",

    # Mobile Security
    "📱 Mobile devices are computers - they need the same security protections!",
    "🔐 Use biometric locks AND strong PINs on mobile devices!",
    "📲 Only install apps from official stores - and check permissions carefully!",
    "🛡️ Enable remote wipe capabilities on all company devices!",

    # Cloud Security
    "☁️ Check your cloud sharing settings - public links can leak sensitive data!",
    "🔐 Use unique passwords for each cloud service!",
    "📊 Review cloud access logs regularly for suspicious activity!",

    # USB & Removable Media
    "💾 Never plug in unknown USB drives - they could contain malware!",
    "🚫 Found a USB stick? Don't plug it in - report it to security!",
    "🔒 Encrypt removable media containing sensitive information!",

    # Remote Work Security
    "🏠 Working from home? Secure your home network like the office!",
    "📹 Cover your webcam when not in use - privacy matters!",
    "🔐 Use a separate VLAN for IoT devices - don't mix with work network!",

    # General Security Culture
    "🛡️ Security is everyone's responsibility - not just IT's job!",
    "⚡ Think before you click - that extra second could save the company!",
    "🎯 Attackers only need to succeed once - defenders must succeed every time!",
    "💡 Stay informed about new threats - knowledge is your best defense!",
    "🔍 Be curious about security - ask questions and learn continuously!",

    # Supply Chain Security
    "📦 Vendor security matters - they're an extension of your security perimeter!",
    "🔗 Third-party integrations should be reviewed by security before deployment!",

    # Monitoring & Awareness
    "👀 Review your account activity logs regularly for suspicious logins!",
    "📧 Check your email forwarding rules - attackers love hidden rules!",
    "🔍 Monitor your credit and identity - data breaches happen!",

    # SOC-specific operational messages
    "🛡️ Cross-referencing threat intelligence databases for your query...",
    "🔍 Diving deep into CrowdStrike telemetry and security logs...",
    "📊 Analyzing patterns across the security ecosystem...",
    "🎯 Correlating events across multiple security platforms...",
    "🔬 Examining incident timelines and forensic artifacts...",
    "🚀 Querying endpoints across the fleet for threat indicators...",
    "💡 Synthesizing threat actor TTPs with current environment...",
    "📡 Analyzing network traffic patterns for anomalies...",
    "🔮 Consulting cybersecurity best practices and frameworks...",
    "🎯 Triangulating data points across security tools..."
]

# Fun completion messages for user engagement
DONE_MESSAGES = [
    "✅ **Done!**",
    "🎉 **Complete!**",
    "⚡ **Finished!**",
    "🎯 **Nailed it!**",
    "🚀 **Mission accomplished!**",
    "🏆 **Success!**",
    "🎪 **Ta-da!**",
    "🌟 **All set!**",
    "🎨 **Masterpiece ready!**",
    "🔥 **Delivered!**",
    "🎵 **And scene!**",
    "🎬 **That's a wrap!**",
    "🎲 **Jackpot!**",
    "🧩 **Puzzle solved!**",
    "⭐ **Mission complete!**",
    "🎯 **Bullseye!**",
    "🏃‍♂️ **Crossed the finish line!**",
    "🎪 **Magic complete!**",
    "🔮 **Oracle consulted!**",
    "📚 **Knowledge delivered!**",
    "🛡️ **Investigation complete!**",
    "🎭 **Performance finished!**",
    "🎸 **Final note played!**",
    "🌈 **Rainbow delivered!**",
    "🔬 **Analysis complete!**",
    "📡 **Signal transmitted!**",
    "🎯 **Target acquired!**",
    "🧠 **Brain power delivered!**",
    "🎪 **Show's over!**",
    "⚙️ **Gears stopped turning!**",
    "🔮 **Crystal ball cleared!**",
    "📊 **Numbers crunched!**",
    "🎨 **Artwork finished!**",
    "🧩 **All pieces found!**",
    "⚡ **Lightning captured!**",
    "🎪 **Curtain call!**",
    "🔍 **Case closed!**",
    "🚀 **Houston, we're done!**",
    "🎭 **Final bow taken!**",
    "🔬 **Lab results in!**",
    "📡 **Transmission ended!**",
    "🎯 **Direct hit achieved!**",
    "🧠 **Mind blown!**",
    "🎪 **Abracadabra complete!**",
    "⚙️ **Engine shut down!**",
    "🔮 **Fortune told!**",
    "📚 **Story complete!**",
    "🎲 **Lucky roll!**",
    "🌟 **Stars aligned!**",
    "🎨 **Brush down!**",
    "🧩 **Eureka achieved!**",
    "⚡ **Power restored!**"
]