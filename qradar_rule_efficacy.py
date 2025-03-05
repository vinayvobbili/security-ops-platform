import matplotlib.pyplot as plt
import pandas as pd

from config import get_config
from incident_fetcher import IncidentFetcher

config = get_config()


def make_chart():
    query = f'type:"{config.ticket_type_prefix} Qradar Alert" -owner:""'
    period = {"byTo": "months", "toValue": 3, "byFrom": "months", "fromValue": None}

    incident_fetcher = IncidentFetcher()
    tickets = incident_fetcher.get_tickets(query=query, period=period)

    # group the tickets by CustomFields.correlationrule. Make horizontal bar graph by corelation rule. Break the bars by impact
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
    # calculate noise of each rule. noise = (ignore + false positive + unknown) / total as percentage
    for rule, impacts in correlation_rule_counts.items():
        total = sum(impacts.values())
        noise = (impacts.get('Ignore', 0) + impacts.get('False Positive', 0) + impacts.get('Unknown', 0)) / total * 100 if total > 0 else 0
        correlation_rule_counts[rule]['Noise'] = noise

    df = pd.DataFrame.from_dict(correlation_rule_counts, orient='index').fillna(0)
    df = df.sort_values(by=df.columns.tolist(), ascending=False)

    # show noise percentage at the end of each horizontal bar as '90% noise'
    for index, row in df.iterrows():
        noise_percentage = row['Noise']
        total_count = sum(row.drop('Noise'))
        plt.text(total_count, index, f'{noise_percentage:.0f}% noise', ha='left', va='center')

    # show only the top 20 noisy rules
    df = df.head(20)

    df.plot(kind='barh', stacked=True, figsize=(10, 6))
    plt.title('QRadar Rule Efficacy')
    plt.xlabel('Number of Tickets (last 3 months)')
    plt.ylabel('Correlation Rule')
    plt.tight_layout()
    plt.savefig('web/static/charts/QR Rule Efficacy.png')
    plt.close()


def main():
    make_chart()


if __name__ == '__main__':
    main()
