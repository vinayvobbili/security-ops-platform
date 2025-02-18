import os

import pandas as pd

from config import get_config  # If you still use a config file for the path

config = get_config()

cell_names_by_shift = {
    'Monday': {
        'morning': {
            'ma': ['C5', 'C6', 'C7', 'C8'],
            'ra': ['D5', 'D6', 'D7]'],
            'sa': ['E5', 'E6', 'E7']
        },
        'evening': {
            'ma': ['C13', 'C14', 'C15', 'C16'],
            'ra': ['D13', 'D14', 'D15'],
            'sa': ['E13', 'E14', 'E15']
        },
        'night': {
            'ma': ['C29', 'C30', 'C31', 'C32'],
            'ra': ['D29', 'D30', 'D31'],
            'sa': ['E29', 'E30', 'E31']
        }
    },
    'Tuesday': {
        'morning': {
            'ma': ['G5', 'G6', 'G7', 'G8'],
            'ra': ['H5', 'H6', 'H7'],
            'sa': ['I5', 'I6', 'I7']
        },
        'evening': {
            'ma': ['G13', 'G14', 'G15', 'G16'],
            'ra': ['H13', 'H14', 'H15'],
            'sa': ['I13', 'I14', 'I15']
        },
        'night': {
            'ma': ['G29', 'G30', 'G31', 'G32'],
            'ra': ['H29', 'H30', 'H31'],
            'sa': ['I29', 'I30', 'I31']
        }
    },
    'Wednesday': {
        'morning': {
            'ma': ['K5', 'K6', 'K7', 'K8'],
            'ra': ['L5', 'L6', 'L7'],
            'sa': ['M5', 'M6', 'M7']
        },
        'evening': {
            'ma': ['K13', 'K14', 'K15', 'K16'],
            'ra': ['L13', 'L14', 'L15'],
            'sa': ['M13', 'M14', 'M15']
        },
        'night': {
            'ma': ['K29', 'K30', 'K31', 'K32'],
            'ra': ['L29', 'L30', 'L31'],
            'sa': ['M29', 'M30', 'M31']
        }
    },
    'Thursday': {
        'morning': {
            'ma': ['O5', 'O6', 'O7', 'O8'],
            'ra': ['P5', 'P6', 'P7'],
            'sa': ['Q5', 'Q6', 'Q7']
        },
        'evening': {
            'ma': ['O13', 'O14', 'O15', 'O16'],
            'ra': ['P13', 'P14', 'P15'],
            'sa': ['Q13', 'Q14', 'Q15']
        },
        'night': {
            'ma': ['O29', 'O30', 'O31', 'O32'],
            'ra': ['P29', 'P30', 'P31'],
            'sa': ['Q29', 'Q30', 'Q31']
        }
    },
    'Friday': {
        'morning': {
            'ma': ['S5', 'S6', 'S7', 'S8'],
            'ra': ['T5', 'T6', 'T7'],
            'sa': ['U5', 'U6', 'U7']
        },
        'evening': {
            'ma': ['S13', 'S14', 'S15', 'S16'],
            'ra': ['T13', 'T14', 'T15'],
            'sa': ['U13', 'U14', 'U15']
        },
        'night': {
            'ma': ['S29', 'S30', 'S31', 'S32'],
            'ra': ['T29', 'T30', 'T31'],
            'sa': ['U29', 'U30', 'U31']
        }
    },
    'Saturday': {
        'morning': {
            'ma': ['W5', 'W6', 'W7', 'W8'],
            'ra': ['X5', 'X6', 'X7'],
            'sa': ['Y5', 'Y6', 'Y7']
        },
        'evening': {
            'ma': ['W13', 'W14', 'W15', 'W16'],
            'ra': ['X13', 'X14', 'X15'],
            'sa': ['Y13', 'Y14', 'Y15']
        },
        'night': {
            'ma': ['W29', 'W30', 'W31', 'W32'],
            'ra': ['X29', 'X30', 'X31'],
            'sa': ['Y29', 'Y30', 'Y31']
        }
    },
    'Sunday': {
        'morning': {
            'ma': ['AA5', 'AA6', 'AA7', 'AA8'],
            'ra': ['AB5', 'AB6', 'AB7'],
            'sa': ['AC5', 'AC6', 'AC7']
        },
        'evening': {
            'ma': ['AA13', 'AA14', 'AA15', 'AA16'],
            'ra': ['AB13', 'AB14', 'AB15'],
            'sa': ['AC13', 'AC14', 'AC15']
        },
        'night': {
            'ma': ['AA29', 'AA30', 'AA31', 'AA32'],
            'ra': ['AB29', 'AB30', 'AB31'],
            'sa': ['AC29', 'AC30', 'AC31']
        }
    }
}


def get_shift_staffing(filepath):  # Takes filepath as argument
    try:
        df = pd.read_excel(filepath, sheet_name='Jan - Feb 2025', engine='openpyxl')  # Specify sheet and engine
        return df
    except FileNotFoundError:
        print(f"Error: File not found at {filepath}")
        return None
    except Exception as e:  # Catch other potential errors (like wrong sheet name)
        print(f"An error occurred while reading the Excel file: {e}")
        return None


def main():
    # Construct filepath. This makes it more flexible.
    # filename = "MET-CIRT SHIELD Daily Work Schedule.xlsx" # Or get this from your config
    filename = config.secops_shift_staffing_filename
    filepath = os.path.join(os.path.dirname(__file__), 'data', filename)  # Update your file path

    schedule_df = get_shift_staffing(filepath)  # Pass the file path here
    if schedule_df is not None:
        print(schedule_df)


if __name__ == "__main__":
    main()
