"""
SecOps Constants and Messages

Contains shift timing constants, file paths, and fun messages for announcements.
"""
import json
from pathlib import Path

from my_config import get_config

config = get_config()
root_directory = Path(__file__).parent.parent.parent


class ShiftConstants:
    """Shift timing and configuration constants."""
    MORNING_START = 270  # 04:30 (4.5 hours * 60)
    AFTERNOON_START = 750  # 12:30 (12.5 hours * 60)
    NIGHT_START = 1230  # 20:30 (20.5 hours * 60)
    TICKET_SHOW_COUNT = 5
    SHIFT_DURATION_HOURS = 8
    EASTERN_TZ = 'US/Eastern'

    # Shift start hours in decimal format (for calculations)
    SHIFT_START_HOURS = {
        'morning': 4.5,
        'afternoon': 12.5,
        'night': 20.5
    }


# File paths
EXCEL_PATH = root_directory / 'data' / 'transient' / 'secOps' / config.secops_shift_staffing_filename
CELL_NAMES_FILE = root_directory / 'data' / 'secOps' / 'cell_names_by_shift.json'
MANAGEMENT_NOTES_FILE = root_directory / 'data' / 'transient' / 'secOps' / 'management_notes.json'


def load_cell_names_by_shift():
    """Load cell names mapping from JSON file."""
    try:
        with open(CELL_NAMES_FILE, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


# Load cell names at module import
cell_names_by_shift = load_cell_names_by_shift()


# Fun messages for Daily Operational Report charts
DOR_CHART_MESSAGES = [
    "📊 Brewing your daily dose of metrics...",
    "🎨 Painting the security landscape...",
    "📈 Charting the course to cyber victory...",
    "🔥 Hot off the press - fresh security stats...",
    "🎯 Bulls-eye! Here come your metrics...",
    "🧙‍♂️ Conjuring operational insights...",
    "🚀 Launching today's security snapshot...",
    "🕵️‍♂️ Uncovering the secrets in the numbers...",
    "🧠 Processing threat intelligence with style...",
    "☕ Your morning metrics with a side of excellence...",
    "🧩 Assembling the security puzzle...",
    "🛡️ Forging your defense dashboard...",
    "🌈 Adding color to your security posture...",
    "🦉 The wise owl brings operational wisdom...",
    "🎪 Step right up for the daily metrics show...",
    "🎭 Presenting today's security performance...",
    "🏆 Championship-level analytics incoming...",
    "🎬 Rolling out the red carpet for your data...",
    "🎻 Orchestrating a symphony of security stats...",
    "🔮 Crystal ball reveals today's metrics...",
    "🌟 Sprinkling stardust on your dashboard...",
    "🎲 Rolling the dice on today's threat landscape...",
    "🧊 Serving up ice-cold analytics...",
    "🦄 Unicorn-powered metrics incoming...",
    "🎺 Trumpeting today's security wins...",
    "🧬 DNA analysis of your security posture...",
    "🎰 Jackpot! Fresh metrics hitting your screen...",
    "🏰 Building your fortress of data...",
    "🎸 Rocking out with threat metrics...",
    "🌊 Surfing the wave of security data...",
    "🍕 Fresh out of the oven - hot metrics...",
    "🎮 Level up! New stats unlocked...",
    "🦅 Eagle-eye view of your operations...",
    "⚡ Lightning-fast metrics delivery...",
    "🎨 Michelangelo wishes he could paint data like this...",
    "🧵 Weaving the tapestry of security excellence...",
    "🏹 Targeting perfection with today's data...",
    "🌋 Erupting with fresh operational insights...",
    "🎩 Abracadabra! Metrics appear...",
    "🦖 T-Rex-sized analytics incoming...",
    "🍿 Grab your popcorn for today's metrics show...",
    "🧲 Magnetically attracted to great data...",
    "🎣 Reeling in the catch of the day...",
    "🦋 Metamorphosis of raw data into beauty...",
    "🎡 Taking you on a metrics rollercoaster...",
    "🧪 Lab results are in! Pure analytical gold...",
    "🗺️ X marks the spot - treasure map of metrics...",
    "🎊 Confetti cannon of operational excellence...",
    "🦁 Roaring into action with today's stats...",
    "🌮 Taco Tuesday energy with Monday metrics...",
]

# Fun messages for shift performance
SHIFT_PERFORMANCE_MESSAGES = [
    "🌟 Previous shift absolutely crushed it!",
    "🎖️ Medal ceremony for the previous shift!",
    "👏 Round of applause for the last crew!",
    "🏅 Here's how the legends before you did...",
    "💪 Previous shift: Making security look easy!",
    "🎭 The previous act was spectacular!",
    "🦸‍♂️ Superhero shift stats incoming...",
    "🔥 The last shift brought the heat!",
    "⭐ Star performance from the previous crew!",
    "🎯 Bullseye! Check out these shift stats...",
    "🏆 Trophy-worthy performance from the last team!",
    "🎪 The previous show was a blockbuster!",
    "🦅 Soaring stats from the eagle-eyed crew!",
    "🎬 Oscar-worthy shift performance!",
    "🌊 Last shift made waves in security!",
    "⚡ Electrifying performance report!",
    "🎸 Previous shift rocked the SOC!",
    "🚀 Blast off! Last crew reached orbit!",
    "🎺 Fanfare for the magnificent shift before!",
    "🦁 The pride has spoken - last shift roared!",
    "🎨 Masterpiece metrics from the previous artists!",
    "🧙‍♂️ Wizardry-level performance unveiled!",
    "🎯 Dead-center performance stats!",
    "🌟 Constellation of excellence from last shift!",
    "🏰 Fortress defended brilliantly by previous guard!",
]

# Fun messages for shift changes
SHIFT_CHANGE_MESSAGES = [
    "🔔 Shift change alert! Fresh defenders incoming...",
    "🌅 The guard is changing! New heroes on deck...",
    "🎺 Sound the horns! Shift transition time...",
    "🚨 New shift, who dis? Let's gooo!",
    "⏰ Ding ding ding! Shift change o'clock!",
    "🔄 Passing the security torch to the next crew...",
    "🎪 Ladies and gentlemen, introducing your new shift!",
    "🦸‍♀️ The next wave of defenders has arrived!",
    "🌟 New shift stepping up to the plate!",
    "🎬 And... action! New shift is live!",
    "🏰 Changing of the guard at the castle!",
    "🌊 Fresh wave of defenders rolling in...",
    "🔥 New shift bringing the fire!",
    "🎭 The stage is set for the next act!",
    "🦅 Fresh eagles taking flight!",
    "⚡ Power-up! New shift activated!",
    "🎮 Player 2 has entered the game!",
    "🚀 Launching the next mission crew!",
    "🎸 New band taking the stage!",
    "🏹 Fresh arrows in the quiver!",
    "🌈 Rainbow bridge to the next shift!",
    "🎯 Targets locked - new shift engaged!",
    "🦁 The pride rotates - new lions on patrol!",
    "🎊 Party time! New shift celebration!",
    "🛡️ Shields up! New defenders ready!",
    "🌟 The next constellation rises!",
    "🎩 Top hats off to the incoming team!",
    "🦸 Avengers... assemble! (New shift edition)",
    "🔮 The prophecy foretold this shift change!",
    "🏆 Championship roster taking the field!",
]

# Ouch, messages for missing charts
CHART_NOT_FOUND_MESSAGES = [
    "🤕 Ouch! That chart went missing...",
    "💥 Ouch! Chart file is playing hide and seek...",
    "😵 Ouch! We lost that chart somewhere...",
    "🆘 Ouch! Chart file took a vacation day...",
    "🤦 Ouch! That chart ghosted us...",
    "💔 Ouch! Chart file broke up with us...",
    "🕵️ Ouch! Chart went into witness protection...",
    "🏃 Ouch! Chart file ran away from home...",
    "🎭 Ouch! Chart missed its curtain call...",
    "🦖 Ouch! Chart got eaten by a data dinosaur...",
    "🧙 Ouch! Chart vanished in a puff of smoke...",
    "🎪 Ouch! Chart left the circus...",
    "🛸 Ouch! Chart got abducted by aliens...",
    "🏴‍☠️ Ouch! Chart walked the plank...",
    "🎩 Ouch! Chart pulled a disappearing act...",
]
