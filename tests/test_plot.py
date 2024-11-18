import unittest
import base64
import io
import matplotlib.pyplot as plt
import pandas as pd
from aging_tickets import generate_plot, get_df  # Assuming these functions are in aging_tickets.py


# Create a sample DataFrame for testing - represent the data your function expects
def create_sample_dataframe():
    data = {'created': ['2024-07-20', '2024-07-20', '2024-07-21', '2024-07-22', '2024-07-23'],
            'type': ['METCIRT Incident', 'METCIRT Incident', 'METCIRT Vulnerability', 'METCIRT Incident', 'METCIRT Phishing']}
    df = pd.DataFrame(data)
    df['created'] = pd.to_datetime(df['created'])

    return df


class TestGeneratePlot(unittest.TestCase):

    def test_generate_plot_success(self):
        # Create a sample list of tickets (replace with your actual ticket data structure)
        df = create_sample_dataframe()
        tickets = df.to_dict('records')  # pandas DataFrame to list of dict
        # Call the function
        result = generate_plot(tickets)
        # Assertions
        self.assertIsNotNone(result)  # Check if the result is not None (meaning it generated something)
        self.assertIsInstance(result, str)  # Check that result is a string (base64 encoded image)
        try:
            base64.b64decode(result)  # Try to decode to ensure its a valid base64 string
        except Exception as e:
            self.fail(f"Invalid base64 string: {e}")  # Fail the test if it's not a valid base64

    def test_generate_plot_empty_tickets(self):

        result = generate_plot([])  # Empty list
        self.assertIsNone(result) # Or assert some default behavior for empty input


    def test_generate_plot_invalid_input(self):
        # Test case with an invalid input type (e.g., None, string, etc.)
        invalid_input = None  # Or "some string", 123, etc.
        with self.assertRaises(AttributeError):  # Expect AttributeError if 'type' not available
            generate_plot(invalid_input)



    def test_get_df(self):  # Example using a simple dataframe, expand as needed
        data = {'created': ['2024-01-01', '2024-01-02'], 'type': ['METCIRT Incident', 'METCIRT Other']}
        tickets = pd.DataFrame(data).to_dict('records')
        df = get_df(tickets)
        self.assertEqual(len(df), 2)
        self.assertEqual(df['type'].tolist(), ['Incident', 'Other'])  # Check the cleaning logic



if __name__ == '__main__':
    unittest.main()