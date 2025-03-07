import json
import re
from datetime import datetime

import matplotlib.pyplot as plt
import pandas as pd
import pytz
from matplotlib import transforms

from config import get_config
from incident_fetcher import IncidentFetcher

eastern = pytz.timezone('US/Eastern')
config = get_config()

with open('data/rule_name_abbreviations.json', 'r') as f:
    rule_name_abbreviations = json.load(f)


def make_chart():
    query = f'type:"{config.ticket_type_prefix} Qradar Alert" -owner:""'
    period = {"byTo": "months", "toValue": 3, "byFrom": "months", "fromValue": None}

    incident_fetcher = IncidentFetcher()
    tickets = incident_fetcher.get_tickets(query=query, period=period)

    if not tickets:
        return

    correlation_rule_counts = {}
    for ticket in tickets:
        correlation_rule = ticket['CustomFields'].get('correlationrule', 'Unknown')
        impact = ticket['CustomFields'].get('impact', 'Unknown')
        if correlation_rule not in correlation_rule_counts:
            correlation_rule_counts[correlation_rule] = {}
        if impact not in correlation_rule_counts[correlation_rule]:
            correlation_rule_counts[correlation_rule][impact] = 0
        correlation_rule_counts[correlation_rule][impact] += 1

    for rule, impacts in correlation_rule_counts.items():
        total = sum(impacts.values())
        noise = round((total - impacts.get('Confirmed', 0) - impacts.get('Testing', 0)) / total * 100) if total > 0 else 0
        correlation_rule_counts[rule]['Noise'] = noise

    unabbreviated_rules = []
    for rule in correlation_rule_counts.keys():
        found = False
        for pattern in rule_name_abbreviations.keys():
            if re.search(pattern, rule, re.IGNORECASE):
                found = True
        if not found:
            unabbreviated_rules.append(rule)

    df = pd.DataFrame.from_dict(correlation_rule_counts, orient='index').fillna(0)
    df['Total'] = df.sum(axis=1)
    df = df.sort_values(by='Total', ascending=False)

    # Apply abbreviations to index
    for pattern, replacement in rule_name_abbreviations.items():
        df.index = df.index.str.replace(pattern, replacement, regex=True, flags=re.IGNORECASE)

    # Convert index to string type before plotting - this is the key fix
    df.index = df.index.astype(str)

    print("Unabbreviated Rule Names:")
    for rule in unabbreviated_rules:
        print(rule)

    noise_series = df['Noise'].head(20)
    df = df.head(20).drop(columns=['Noise', 'Total'])

    impact_colors = {
        "Significant": "#ff0000",
        "Confirmed": "#ffa500",
        "Detected": "#ffd700",
        "Prevented": "#008000",
        "Ignore": "#808080",
        "Testing": "#add8e6",
        "False Positive": "#90ee90",
    }

    fig, ax = plt.subplots(figsize=(14, 8))

    # Plot with explicit index positions
    df.plot(kind='barh', stacked=True, ax=ax, color=[impact_colors.get(x, "#cccccc") for x in df.columns])

    # Set y-ticks with numeric positions
    y_labels = df.index.tolist()
    ax.set_yticks(range(len(y_labels)))
    ax.set_yticklabels(y_labels)

    ax.legend(title="Impact", loc='upper right', fontsize=10, title_fontsize=10)

    now_eastern = datetime.now(eastern).strftime('%m/%d/%Y %I:%M %p %Z')
    trans = transforms.blended_transform_factory(fig.transFigure, fig.transFigure)
    fig.text(0.08, 0.01, now_eastern, ha='left', va='bottom', fontsize=10, transform=trans)
    fig.text(0.75, 0.001, 'Noise = (Total - Confirmed - Testing) / Total * 100%', ha='left', va='bottom', fontsize=10, transform=trans)

    # Add text labels to bars
    for i, row in enumerate(df.iterrows()):
        left = 0
        for value in row[1].values:  # Access values from the Series in row[1]
            if value > 0:
                ax.text(left + value / 2, i, int(value), ha='center', va='center')
            left += float(value)

    plt.title('QRadar Rule Efficacy (Top 20 by Volume)', fontsize=12, pad=10, fontweight='bold')
    plt.xlabel('Number of Tickets (last 3 months)', fontsize=10, labelpad=10, fontweight='bold')
    plt.ylabel('Correlation Rule', fontweight='bold', fontsize=10)

    # Add noise percentage labels
    for i, noise in enumerate(noise_series):
        total_width = df.iloc[i].sum()
        ax.text(total_width, i, f'  {int(noise)}% noise', va='center', ha='left', fontsize=10)

    plt.tight_layout()
    plt.savefig('web/static/charts/QR Rule Efficacy.png')
    plt.close()


def main():
    make_chart()


if __name__ == '__main__':
    main()
