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

# Category-specific thinking messages — shown after the router picks tool categories.
# Keys MUST match the ids in my_bot/core/state_manager.py:TOOL_CATEGORIES (plus
# `local_docs`, which is added at runtime when the RAG retriever is loaded).
# Tone: short, emoji-prefixed, slightly playful — matches THINKING_MESSAGES above.
CATEGORY_THINKING_MESSAGES = {
    "crowdstrike": [
        "🦅 Querying CrowdStrike Falcon telemetry...",
        "💻 Checking host containment status in Falcon...",
        "🛡️ Scanning Falcon detections across the fleet...",
        "🔍 Pulling device details from CrowdStrike...",
        "🚨 Reviewing recent Falcon incidents...",
        "📡 Asking the Falcon sensor what it has seen...",
    ],
    "xsoar": [
        "🎫 Pulling the XSOAR ticket...",
        "📋 Reading incident details from Cortex XSOAR...",
        "🧾 Reviewing analyst verdicts on this case...",
        "🔄 Triaging the ticket through XSOAR enrichment...",
        "📝 Composing an executive summary...",
        "🗂️ Cross-referencing related XSOAR incidents...",
    ],
    "virustotal": [
        "🦠 Checking reputation in VirusTotal...",
        "🔬 Pulling VT engine verdicts...",
        "🌐 Looking up the IOC across 70+ AV engines...",
        "📊 Reviewing VT community votes...",
        "🧪 Asking VirusTotal what it knows...",
    ],
    "abuseipdb": [
        "🚫 Checking AbuseIPDB reports...",
        "📛 Pulling the IP's abuse confidence score...",
        "🌍 Asking AbuseIPDB about this address...",
        "🛑 Reviewing recent abuse reports...",
    ],
    "urlscan": [
        "🔗 Submitting the URL to urlscan.io...",
        "📸 Pulling historical urlscan results...",
        "🌐 Checking the URL's render history...",
        "🕵️ Asking urlscan what this domain looks like...",
    ],
    "shodan": [
        "📡 Asking Shodan about exposed services...",
        "🔌 Pulling open ports from Shodan...",
        "🌐 Checking Shodan for this host's footprint...",
        "🔎 Reviewing service banners on Shodan...",
    ],
    "intelx": [
        "🕶️ Searching IntelligenceX for leaks...",
        "🌑 Diving into dark web mentions...",
        "🔓 Checking for credential exposure...",
        "📂 Asking IntelX about leaked data...",
    ],
    "abusech": [
        "🦠 Checking abuse.ch malware feeds...",
        "🤖 Looking up botnet C2 indicators...",
        "🛑 Asking abuse.ch about this IOC...",
        "📛 Reviewing abuse.ch blocklists...",
    ],
    "tanium": [
        "💻 Asking Tanium endpoints across the fleet...",
        "🔍 Looking up the host in Tanium...",
        "📡 Pulling Tanium endpoint details...",
        "🛡️ Checking what Tanium sees on this machine...",
    ],
    "qradar": [
        "🔍 Querying QRadar SIEM...",
        "📊 Building an AQL query...",
        "📈 Searching QRadar event logs...",
        "🚨 Reviewing QRadar offenses...",
        "🧮 Translating your question into AQL...",
        "📡 Asking QRadar to crunch the logs...",
    ],
    "vectra": [
        "🛰️ Asking Vectra about network detections...",
        "🚨 Pulling high-priority Vectra threats...",
        "🔍 Searching Vectra for this entity...",
        "📡 Reviewing Vectra entity scores...",
    ],
    "servicenow": [
        "🗃️ Looking up the host in ServiceNow CMDB...",
        "📋 Pulling the configuration item from SNOW...",
        "🏢 Checking asset ownership in ServiceNow...",
        "🔎 Asking SNOW about this device...",
    ],
    "varonis": [
        "📂 Checking Varonis DatAlert events...",
        "👤 Pulling user data activity from Varonis...",
        "🛡️ Reviewing Varonis alerts for this user...",
        "🔍 Asking Varonis what files were touched...",
    ],
    "active_directory": [
        "🏛️ Querying Active Directory...",
        "👤 Pulling AD user account details...",
        "💻 Looking up the computer object in AD...",
        "🔐 Checking group membership and OU...",
        "⏰ Reviewing last logon timestamps...",
    ],
    "recorded_future": [
        "🌐 Asking Recorded Future for threat intel...",
        "🎯 Pulling Recorded Future risk scores...",
        "📡 Checking Recorded Future for this IOC...",
        "🦹 Looking up the threat actor in Recorded Future...",
        "🔬 Reviewing Recorded Future evidence...",
    ],
    "tipper": [
        "📰 Analyzing the threat intel report...",
        "🧪 Checking tipper novelty against history...",
        "🔍 Extracting IOCs from the text...",
        "📝 Adding analyst notes to the tipper...",
    ],
    "thehive": [
        "🐝 Working with TheHive case management...",
        "📋 Pulling TheHive case details...",
        "📎 Adding observables to TheHive...",
        "🔍 Searching TheHive cases...",
    ],
    "dfir_iris": [
        "🌸 Working with DFIR-IRIS...",
        "📋 Pulling the IRIS case...",
        "📎 Adding IOCs to the IRIS case...",
        "🕒 Updating IRIS timeline events...",
    ],
    "contacts": [
        "📇 Looking up escalation contacts...",
        "👥 Pulling the regional contact list...",
        "📞 Checking who to escalate this to...",
        "🗺️ Finding the right team contact...",
    ],
    "staffing": [
        "🕒 Checking the current SOC shift...",
        "👥 Pulling who's on duty right now...",
        "📅 Reviewing the shift schedule...",
        "🌍 Finding the on-call analyst...",
    ],
    "weather": [
        "🌤️ Checking the forecast...",
        "🌡️ Pulling current weather conditions...",
        "☁️ Asking the weather service...",
        "🌦️ Looking up local weather...",
    ],
    "testing": [
        "🧪 Running diagnostic tests...",
        "🔧 Sending a test message...",
        "✅ Verifying bot connectivity...",
        "🛠️ Checking the wiring...",
    ],
    "web_search": [
        "🌐 Searching the web for current info...",
        "🔍 Looking up recent news and disclosures...",
        "📰 Pulling fresh results from the web...",
        "🌍 Checking the open internet...",
        "📡 Asking the search engine...",
    ],
    "memory": [
        "🧠 Recalling team knowledge...",
        "📚 Searching saved memories...",
        "💾 Checking what the team has taught me...",
        "🗒️ Looking through team notes...",
    ],
    "block_url": [
        "🚫 Preparing the URL block request...",
        "🛑 Routing the block through XSOAR...",
        "🔒 Building the block confirmation card...",
        "📛 Queuing the URL for blocking...",
    ],
    "diagrams": [
        "🎨 Rendering the diagram...",
        "🖼️ Sketching the attack flow...",
        "📐 Composing the Mermaid source...",
        "🌈 Coloring the nodes...",
        "🚀 Sending the rendered diagram to Webex...",
    ],
    "local_docs": [
        "📚 Searching local SOC runbooks...",
        "📖 Pulling from the GDnR response guides...",
        "🔍 Checking internal procedure docs...",
        "📋 Reading the relevant playbook...",
        "🗂️ Asking the local document index...",
    ],
}


# Human-friendly display names for tool categories — used by the security assistant bot's
# "🎯 Tools loaded: ..." status edit fired immediately after the router decides.
# Keys MUST match TOOL_CATEGORIES ids (and CATEGORY_THINKING_MESSAGES keys).
# Any category id without an entry falls back to title-cased id.
CATEGORY_DISPLAY_NAMES = {
    "crowdstrike": "CrowdStrike",
    "xsoar": "XSOAR",
    "virustotal": "VirusTotal",
    "abuseipdb": "AbuseIPDB",
    "urlscan": "urlscan.io",
    "shodan": "Shodan",
    "intelx": "IntelX",
    "abusech": "abuse.ch",
    "tanium": "Tanium",
    "qradar": "QRadar",
    "vectra": "Vectra",
    "servicenow": "ServiceNow",
    "varonis": "Varonis",
    "active_directory": "Active Directory",
    "recorded_future": "Recorded Future",
    "tipper": "Tipper",
    "thehive": "TheHive",
    "dfir_iris": "DFIR-IRIS",
    "contacts": "Contacts",
    "staffing": "Staffing",
    "weather": "Weather",
    "testing": "Bot Testing",
    "web_search": "Web Search",
    "memory": "Memory",
    "block_url": "URL Block",
    "diagrams": "Diagrams",
    "local_docs": "Local Docs",
}


# the Windows triage agent thinking messages — teaching tips from AI, LLMs, and Python
MENTOR_THINKING_MESSAGES = [
    # LLMs & transformers
    "🧠 LLM tip: Transformers use self-attention to weigh every token against every other token in a sequence — that's why context length matters so much!",
    "🤖 LLM tip: Temperature controls randomness — 0.0 is deterministic, 1.0 is creative. Most production bots use 0.1–0.3 for factual tasks.",
    "💡 LLM tip: 'Hallucination' happens when a model generates plausible-sounding but false information. RAG helps by grounding answers in real documents.",
    "🔮 LLM tip: A 7B model has 7 billion parameters — each is a floating-point weight learned during training. Quantization shrinks these to 4-bit to save memory.",
    "⚡ LLM tip: Prefill (processing your prompt) and decode (generating tokens) are separate phases. Long prompts are slow to prefill but fast to decode.",
    "🎯 LLM tip: 'Context window' is the max tokens the model can see at once. Exceeding it causes older context to be silently dropped.",
    "🌡️ LLM tip: Top-p (nucleus) sampling picks from the smallest set of tokens whose probabilities sum to p — it's often combined with temperature.",
    "🔑 LLM tip: System prompts set the model's persona and rules. They come before the conversation and are the most influential part of the prompt.",
    "📐 LLM tip: Chain-of-thought prompting (\"think step by step\") dramatically improves reasoning — it forces the model to show its work before answering.",
    "🏗️ LLM tip: Tool calling lets an LLM invoke real functions — the model outputs a JSON spec, your code runs the function, and the result goes back to the model.",

    # RAG & embeddings
    "🔍 RAG tip: Retrieval-Augmented Generation fetches relevant documents at query time and injects them into the prompt — no retraining needed!",
    "📡 RAG tip: Embeddings are dense vectors that capture semantic meaning. Similar sentences end up close together in vector space — that's how semantic search works.",
    "🗄️ RAG tip: ChromaDB stores embeddings alongside their source text. At query time, your question is embedded and compared against all stored vectors using cosine similarity.",
    "✂️ RAG tip: Chunking strategy matters a lot. Too small = lost context. Too large = noisy retrieval. Overlapping chunks (like 1200 chars / 200 overlap) help preserve boundaries.",
    "🧬 RAG tip: The embedding model and the generation model are separate! You can use a small, fast model (like Qwen3-Embedding-8B) just for embeddings.",

    # Python
    "🐍 Python tip: Generators use `yield` instead of `return` — they produce values one at a time, keeping memory usage flat even for huge datasets.",
    "🐍 Python tip: `@dataclass` auto-generates `__init__`, `__repr__`, and `__eq__` from your field annotations — less boilerplate than writing them by hand.",
    "🐍 Python tip: `asyncio` lets a single thread handle thousands of I/O-bound tasks concurrently. The trick: `await` suspends the current task while waiting, freeing the event loop.",
    "🐍 Python tip: List comprehensions `[x for x in items if cond]` are faster than equivalent `for` loops because they're optimized at the bytecode level.",
    "🐍 Python tip: `functools.lru_cache` memoizes function results — great for expensive computations you call repeatedly with the same arguments.",
    "🐍 Python tip: Type hints don't enforce types at runtime — they're for static analysis tools like mypy and for making code self-documenting.",
    "🐍 Python tip: `with` statements use the context manager protocol (`__enter__` / `__exit__`) — perfect for resources that need guaranteed cleanup like files and DB connections.",
    "🐍 Python tip: Pydantic validates data at runtime using Python type annotations — it's the engine behind FastAPI request parsing and LangChain model definitions.",

    # AI concepts
    "🎓 AI tip: Fine-tuning adapts a pre-trained model to a specific task by training on a small labelled dataset. It's much cheaper than training from scratch.",
    "🎓 AI tip: RLHF (Reinforcement Learning from Human Feedback) is how ChatGPT was trained to follow instructions — humans rank outputs, and those rankings train a reward model.",
    "🎓 AI tip: Tokens ≠ words. 'unbelievable' might be 3 tokens: 'un', 'believ', 'able'. Most models average ~0.75 words per token for English.",
    "🎓 AI tip: KV cache stores attention keys and values from previous tokens so the model doesn't recompute them on each new token — it's why generation gets faster after the first token.",
    "🎓 AI tip: Mixture of Experts (MoE) models like Qwen3.5-35B-A3B activate only a subset of parameters per token — efficient because you get a large model at the cost of a small one.",

    # LLMs & transformers (continued)
    "🧠 LLM tip: 'Grounding' means tying model outputs to verifiable sources. RAG, tool calling, and citations are all grounding techniques.",
    "🤖 LLM tip: Prompt injection is when malicious user input tries to override system instructions. Always treat user content as untrusted data.",
    "💡 LLM tip: Few-shot prompting gives the model 2–5 examples of the desired input/output format before the real question — it dramatically improves structured outputs.",
    "⚡ LLM tip: Beam search generates multiple candidate sequences in parallel and picks the highest-probability one. Slower than greedy but often more coherent.",
    "🔑 LLM tip: 'Lost in the middle' — studies show LLMs perform worse on information placed in the middle of long contexts vs. the beginning or end.",
    "🎯 LLM tip: Instruction-tuned models (like Qwen3-Instruct) are fine-tuned to follow directions. Base models are better for completion tasks, instruct models for chat.",
    "🏗️ LLM tip: Multi-turn conversation is just a long prompt. The entire chat history is concatenated and sent to the model each time — there's no built-in memory.",
    "🌡️ LLM tip: Repetition penalty discourages the model from repeating the same tokens. Useful for long generations that tend to loop.",
    "📐 LLM tip: Structured output (JSON mode) constrains the model's vocabulary using a grammar — only tokens that keep the output valid JSON are allowed.",
    "🔮 LLM tip: Speculative decoding uses a tiny draft model to propose tokens, then the big model verifies them in parallel — can double throughput.",
    "🧬 LLM tip: Attention heads in a transformer each learn different relationships — some track syntax, some track coreference, some track position.",
    "🔍 LLM tip: The 'softmax bottleneck' limits how many distinct distributions a model can represent. Mixture of Softmaxes and larger vocab sizes help.",
    "📡 LLM tip: Flash Attention rewrites the attention computation to be memory-efficient by never materializing the full attention matrix — critical for long contexts.",
    "🎓 LLM tip: GGUF is a binary format for quantized models — it packs weights efficiently and supports CPU+GPU offloading. The format that llama.cpp uses.",
    "🌐 LLM tip: vllm uses continuous batching and PagedAttention to serve many users efficiently — it's why throughput is much higher than naive inference.",

    # RAG & embeddings (continued)
    "🔍 RAG tip: Hybrid search combines dense vector search (semantic) with sparse BM25 search (keyword). The union often beats either alone.",
    "📡 RAG tip: Re-ranking is a second-pass step that re-scores retrieved chunks using a cross-encoder — more accurate than cosine similarity alone.",
    "🗄️ RAG tip: Metadata filtering lets you scope retrieval to a subset of your index (e.g. only Python files). Always expose metadata at index time.",
    "✂️ RAG tip: Sentence-window retrieval stores small chunks for precision but fetches the surrounding window at query time for context.",
    "🧬 RAG tip: Multi-query RAG generates several rephrased versions of your question and merges results — great for ambiguous queries.",
    "💾 RAG tip: Embedding drift happens when your index was built with one model version but queries use another. Always rebuild the index when changing models.",
    "🎯 RAG tip: The 'lost in retrieval' problem: if the right chunk isn't in the top-k results, no amount of LLM reasoning can fix it. Retrieval quality is the ceiling.",
    "🔗 RAG tip: Knowledge graphs can complement vector RAG — they capture explicit relationships (A→caused by→B) that embeddings may miss.",
    "⚙️ RAG tip: Cosine similarity measures the angle between two vectors, not their magnitude. Normalizing embeddings to unit length makes dot product == cosine similarity.",
    "🌡️ RAG tip: Parent-child chunking stores fine-grained chunks for retrieval but returns their parent chunk for context — balances precision and completeness.",

    # Python (continued)
    "🐍 Python tip: `__slots__` prevents dynamic attribute creation and can cut memory usage by 40–70% for classes you create millions of instances of.",
    "🐍 Python tip: `pathlib.Path` is the modern replacement for `os.path`. `Path('a') / 'b' / 'c.txt'` is much cleaner than `os.path.join('a', 'b', 'c.txt')`.",
    "🐍 Python tip: `collections.defaultdict` auto-creates missing keys with a factory — great for grouping: `d = defaultdict(list); d['key'].append(val)`.",
    "🐍 Python tip: The walrus operator `:=` assigns and tests in one step: `if (n := len(data)) > 10: print(n)` — avoids calling `len()` twice.",
    "🐍 Python tip: `itertools.chain` lazily concatenates iterables without building a combined list in memory — useful for streaming large datasets.",
    "🐍 Python tip: `threading.Event` is the cleanest way to signal between threads — `event.set()` wakes all waiters, `event.clear()` resets it.",
    "🐍 Python tip: `contextlib.suppress(Exception)` is the idiomatic way to silently ignore specific exceptions — cleaner than a bare `try/except: pass`.",
    "🐍 Python tip: f-strings support format specs: `f'{value:.2f}'`, `f'{name!r}'`, `f'{num:>10}'`. You rarely need `%` formatting or `.format()` anymore.",
    "🐍 Python tip: `logging` is preferable to `print` for production code — it supports levels, handlers, formatters, and can be silenced without code changes.",
    "🐍 Python tip: `__init_subclass__` lets a base class hook into subclass creation — useful for auto-registration patterns without metaclasses.",
    "🐍 Python tip: Avoid mutable default arguments: `def f(lst=[])` shares the list across all calls. Use `def f(lst=None): lst = lst or []` instead.",
    "🐍 Python tip: `zip(a, b, strict=True)` raises `ValueError` if the iterables have different lengths — catches bugs that silent truncation would hide.",
    "🐍 Python tip: `abc.ABC` and `@abstractmethod` enforce that subclasses implement specific methods — Python's way of defining interfaces.",
    "🐍 Python tip: `multiprocessing` bypasses the GIL for CPU-bound work by using separate processes. For I/O-bound work, `asyncio` or `threading` is enough.",
    "🐍 Python tip: `__repr__` should return a string that could recreate the object. `__str__` is for human-readable output. `print()` calls `__str__` first.",
    "🐍 Python tip: Global Interpreter Lock (GIL) means only one thread runs Python bytecode at a time. It's being removed incrementally in Python 3.13+.",

    # AI concepts (continued)
    "🎓 AI tip: LoRA (Low-Rank Adaptation) fine-tunes only a tiny set of adapter weights instead of the full model — 1000x fewer trainable parameters, similar results.",
    "🎓 AI tip: Perplexity measures how surprised a model is by a text. Lower = more confident. It's the standard metric for evaluating language model quality.",
    "🎓 AI tip: Guardrails are post-processing filters that check model output for toxicity, PII, or policy violations before it reaches the user.",
    "🎓 AI tip: An agent is an LLM in a loop — it can call tools, observe results, and decide the next action until a stopping condition is met.",
    "🎓 AI tip: Prompt caching saves the key-value computation of a repeated prefix. If your system prompt never changes, the provider only processes it once.",
    "🎓 AI tip: Model distillation trains a small 'student' model to mimic a large 'teacher' model's outputs — you get most of the quality at a fraction of the cost.",
    "🎓 AI tip: Sparse attention (like Longformer) makes each token attend only to nearby tokens and a few global ones — reduces attention cost from O(n²) to O(n).",
    "🎓 AI tip: Positional encoding gives the model information about token order. RoPE (Rotary Position Embedding) is the dominant method in modern LLMs.",
    "🎓 AI tip: MMLU (Massive Multitask Language Understanding) is a common benchmark — 57 subjects from elementary math to law. Useful for comparing model capability.",
    "🎓 AI tip: The scaling laws paper showed that model performance improves predictably with more compute, data, and parameters — this insight drove the LLM boom.",
    "🎓 AI tip: Inference is running a trained model to get outputs. Training is updating weights. Inference is ~10–100x cheaper per token than training.",
    "🎓 AI tip: Apple Silicon's unified memory means the GPU and CPU share the same RAM pool — which is why a 64GB M1 can run a 40B quantized model locally.",
    "🎓 AI tip: BPE (Byte-Pair Encoding) is how most LLM tokenizers are built — it iteratively merges the most frequent byte pairs into single tokens.",
    "🎓 AI tip: Constitutional AI (CAI) trains models to critique and revise their own outputs according to a set of principles — used by Anthropic for Claude.",
    "🎓 AI tip: Multi-modal models like GPT-4V process text and images in the same transformer by projecting image patches into the token embedding space.",

    # LLMs — advanced
    "🧠 LLM tip: Logit bias lets you boost or suppress specific tokens before sampling — useful for forcing JSON keys or banning certain words entirely.",
    "🤖 LLM tip: 'Jailbreaking' exploits gaps between the model's training objective and its safety fine-tune. Adversarial inputs find edge cases the RLHF didn't cover.",
    "💡 LLM tip: Constrained decoding (outlines, guidance) guarantees valid structured output by masking invalid tokens at each step — more reliable than asking nicely.",
    "⚡ LLM tip: Throughput (tokens/sec across all users) and latency (time to first token for one user) are different trade-offs — batching improves throughput but hurts latency.",
    "🎯 LLM tip: Quantization converts 16-bit weights to 4-bit, reducing model size by ~75%. Quality loss is minimal for 4-bit on large models; significant on small ones.",
    "🔮 LLM tip: The 'reversal curse' — models trained on 'A is B' often can't answer 'what is B?' because training data has directional bias.",

    # RAG — advanced
    "🔍 RAG tip: Contextual compression post-processes retrieved chunks to extract only the sentences relevant to the query — reduces noise sent to the LLM.",
    "📡 RAG tip: HNSW (Hierarchical Navigable Small World) is the graph index behind most fast ANN search — it trades a small accuracy loss for orders-of-magnitude speedup.",
    "🗄️ RAG tip: Incremental indexing only re-embeds changed documents instead of rebuilding from scratch — essential for large, frequently-updated corpora.",

    # Python — advanced
    "🐍 Python tip: `__class_getitem__` is what makes generics like `list[int]` work. You can implement it yourself to create subscriptable custom classes.",
    "🐍 Python tip: `sys.getsizeof()` returns the shallow size of an object in bytes. For the deep size (including referenced objects), use `tracemalloc` or `objgraph`.",
    "🐍 Python tip: Descriptors (`__get__`, `__set__`, `__delete__`) are what power `@property`, `@classmethod`, and ORMs like SQLAlchemy under the hood.",
    "🐍 Python tip: `concurrent.futures.ThreadPoolExecutor` is the easiest way to run I/O-bound tasks in parallel — `executor.map(fn, items)` is just like `map()`.",
    "🐍 Python tip: `__all__` in a module controls what `from module import *` exports — good practice to define it explicitly in any public API module.",
    "🐍 Python tip: `weakref` lets you reference an object without preventing garbage collection — useful for caches and event listeners that shouldn't keep objects alive.",

    # AI — practical
    "🎓 AI tip: Eval-driven development: before building an AI feature, define how you'll measure if it works. Without evals, you're flying blind.",
    "🎓 AI tip: LLM APIs charge by token. A typical page of text is ~500 tokens. A 100K-token context window holds roughly 200 pages.",
    "🎓 AI tip: Semantic versioning doesn't apply to LLMs — the same model name can behave differently after a provider update. Pin model versions in production.",
    "🎓 AI tip: Agentic loops can get stuck. Always set a max-iteration limit and a wall-clock timeout — otherwise one stuck tool call hangs forever.",
    "🎓 AI tip: The best way to improve RAG quality isn't a better model — it's better chunking, better metadata, and better queries sent to the retriever.",
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