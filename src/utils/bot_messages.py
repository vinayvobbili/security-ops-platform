# /src/utils/bot_messages.py
"""
Bot engagement messages for user interaction
"""

# Fun thinking messages for user engagement
THINKING_MESSAGES = [
    "🤔 Thinking...", "🧠 Processing...", "⚡ Computing...", "🔍 Searching...",
    "🎯 Analyzing...", "🛡️ Investigating...", "📊 Calculating...", "🔬 Examining...",
    "💭 Pondering...", "🎪 Working magic...", "🚀 Launching queries...", "⚙️ Turning gears...",
    "🔮 Consulting oracles...", "📚 Reading docs...", "🎲 Rolling dice...", "🌟 Connecting dots...",
    "🎨 Crafting response...", "🏃‍♂️ Running analysis...", "🔥 Firing neurons...", "⭐ Aligning stars...",
    "🎯 Taking aim...", "🧩 Solving puzzle...", "🎪 Performing magic...", "🚁 Hovering over data...",
    "🎭 Putting on thinking cap...", "🔍 Zooming in...", "⚡ Charging up...", "🎨 Painting picture...",
    "🧠 Flexing brain...", "🎪 Juggling ideas...", "🔬 Under microscope...", "📡 Scanning frequencies...",
    "🎯 Zeroing in...", "🚀 Rocket science mode...", "🎲 Calculating odds...", "⚙️ Oiling gears...",
    "🔮 Crystal ball active...", "📊 Crunching numbers...", "🎨 Mixing colors...", "🧩 Finding pieces...",
    "⚡ Lightning speed...", "🎪 Center stage...", "🔍 Detective mode...", "🌟 Seeing stars...",
    "🎭 Method acting...", "🚁 Bird's eye view...", "🔬 Lab coat on...", "📡 Signal strong...",
    "🎯 Bullseye incoming...", "🧠 Big brain time...", "🎪 Grand finale prep...", "⚙️ All systems go...",
    "🔮 Fortune telling...", "📚 Page turning...", "🎲 Lucky number 7...", "🌟 Constellation forming...",
    "🎨 Masterpiece loading...", "🧩 Last piece hunting...", "⚡ Storm brewing...", "🎪 Showtime prep...",
    "🔍 Magnifying glass out...", "🚀 T-minus counting...", "🎭 Oscar performance...", "🔬 Hypothesis testing...",
    "📡 Satellite locked...", "🎯 Perfect aim...", "🧠 Neural networks firing...", "🎪 Magic wand waving...",
    "⚙️ Clockwork precision...", "🔮 Third eye opening...", "📊 Graph plotting...", "🎲 Dice rolling...",
    "🌟 Supernova incoming...", "🎨 Canvas ready...", "🧩 Pattern matching...", "⚡ Thunder rumbling...",
    "🎪 Spotlight on...", "🔍 Sherlock mode...", "🚀 Warp speed...", "🎭 Drama unfolding...",
    "🔬 Microscope focused...", "📡 Transmission clear...", "🎯 Target acquired...", "🧠 Synapse snapping...",
    "🎪 Ringmaster ready...", "⚙️ Engine revving...", "🔮 Visions coming...", "📚 Chapter turning...",
    "🎲 Fortune favors...", "🌟 Galaxy spinning...", "🎨 Brush stroking...", "🧩 Eureka moment...",
    "⚡ Power surge...", "🎪 Curtain rising...", "🔍 Clue hunting...", "🚀 Orbit achieved...",
    "🎭 Scene stealing...", "🔬 Specimen ready...", "📡 Message received...", "🎯 Direct hit...",
    "🧠 Mind melding...", "🎪 Abracadabra...", "⚙️ Turbine spinning...", "🔮 Cards revealing...",
    "📊 Trend spotting...", "🎲 Snake eyes...", "🌟 Comet approaching...", "🎨 Sketch complete...",
    "🧩 Jigsaw solving...", "⚡ Electric moment...", "🎪 Ta-da incoming...", "🔍 Evidence gathering...",
    "🚀 Houston, we have...", "🎭 Standing ovation...", "🔬 Breakthrough near...", "📡 Signal boosted...",
    "🎯 Championship shot...", "🧠 Genius at work...", "🎪 Grand illusion...", "⚙️ Perfect timing...",
    "🔮 Future glimpse...", "📚 Story unfolding...", "🎲 Jackpot hunting...", "🌟 Wish upon a...",
    "🎨 Final touches...", "🧩 Missing link...", "⚡ Lightning strikes...", "🎪 Magic revealed...",
    # Longer, more conversational SOC-specific messages
    "🛡️ Cross-referencing threat intelligence databases for your query...",
    "🔍 Diving deep into CrowdStrike telemetry and security logs...",
    "📊 Analyzing staffing patterns and shift rotations...",
    "🌦️ Checking weather conditions that might affect operations...",
    "🎯 Correlating events across multiple security platforms...",
    "🔬 Examining incident timelines and forensic artifacts...",
    "🚀 Launching comprehensive endpoint queries across the fleet...",
    "💡 Synthesizing threat actor TTPs with current environment...",
    "🎪 Orchestrating a symphony of security data points...",
    "⚙️ Fine-tuning detection algorithms for maximum precision...",
    "🔮 Predicting attack vectors using machine learning models...",
    "📡 Intercepting and analyzing network traffic patterns...",
    "🛡️ Consulting my vast knowledge of cybersecurity best practices...",
    "🎯 Triangulating data points across the security ecosystem...",
    "🔬 Performing behavioral analysis on network traffic patterns...",
    "🚀 Launching comprehensive security posture assessments...",
    "💡 Connecting security dots that humans might miss...",
    "🎭 Putting on my best security analyst persona for you..."
]

# Fun completion messages for user engagement
DONE_MESSAGES = [
    "✅ **Done!**", "🎉 **Complete!**", "⚡ **Finished!**", "🎯 **Nailed it!**",
    "🚀 **Mission accomplished!**", "🏆 **Success!**", "🎪 **Ta-da!**", "🌟 **All set!**",
    "🎨 **Masterpiece ready!**", "🔥 **Delivered!**", "🎵 **And scene!**", "🎬 **That's a wrap!**",
    "🎲 **Jackpot!**", "🧩 **Puzzle solved!**", "⭐ **Mission complete!**", "🎯 **Bullseye!**",
    "🏃‍♂️ **Crossed the finish line!**", "🎪 **Magic complete!**", "🔮 **Oracle consulted!**", "📚 **Knowledge delivered!**",
    "🛡️ **Investigation complete!**", "🎭 **Performance finished!**", "🎸 **Final note played!**", "🌈 **Rainbow delivered!**",
    "🔬 **Analysis complete!**", "📡 **Signal transmitted!**", "🎯 **Target acquired!**", "🧠 **Brain power delivered!**",
    "🎪 **Show's over!**", "⚙️ **Gears stopped turning!**", "🔮 **Crystal ball cleared!**", "📊 **Numbers crunched!**",
    "🎨 **Artwork finished!**", "🧩 **All pieces found!**", "⚡ **Lightning captured!**", "🎪 **Curtain call!**",
    "🔍 **Case closed!**", "🚀 **Houston, we're done!**", "🎭 **Final bow taken!**", "🔬 **Lab results in!**",
    "📡 **Transmission ended!**", "🎯 **Direct hit achieved!**", "🧠 **Mind blown!**", "🎪 **Abracadabra complete!**",
    "⚙️ **Engine shut down!**", "🔮 **Fortune told!**", "📚 **Story complete!**", "🎲 **Lucky roll!**",
    "🌟 **Stars aligned!**", "🎨 **Brush down!**", "🧩 **Eureka achieved!**", "⚡ **Power restored!**"
]