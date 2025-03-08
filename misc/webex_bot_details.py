from webexteamssdk import WebexTeamsAPI

from config import get_config


def get_bot_details(bot_access_token):
    """
    Get the details of the Webex bot using its access token.
    Args:
        bot_access_token (str): The access token for the Webex bot.
    Returns:
        dict: A dictionary containing bot details (id, displayName, emails) or None if an error occurs.
    """
    try:
        api = WebexTeamsAPI(access_token=bot_access_token)
        person = api.people.me()
        return {
            "id": person.id,
            "displayName": person.displayName,
            "emails": person.emails
        }
    except Exception as e:
        print(f"Error getting bot details: {e}")
        return None


def main():
    config = get_config()
    bot_access_token = config.webex_bot_access_token_moneyball
    bot_details = get_bot_details(bot_access_token)
    if bot_details:
        print(f"Bot ID: {bot_details['id']}")
        print(f"Bot Name: {bot_details['displayName']}")
        print(f"Bot Email: {bot_details['emails']}")
    else:
        print("Could not get bot details.")


if __name__ == "__main__":
    main()
