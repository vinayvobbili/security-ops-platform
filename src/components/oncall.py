import datetime
from datetime import date, timedelta

def get_on_call_person():
    """get on-call from XSOAR lists"""
    today = datetime.now(timezone('EST'))
    last_monday = today - timedelta(days=today.weekday())
    return get_on_call_email_by_monday_date(last_monday.strftime('%Y-%m-%d'))

def __get_on_call_email_by_monday_date__(monday_date):
    """takes the Monday_date as arg"""
    t3_on_call_list = list_handler.get_list_by_name('Spear_OnCall')
    analysts, rotation = get_on_call_details()
    on_call_name = list(
        filter(
            lambda x: x['Monday_date'] == str(monday_date),
            rotation
        )
    )[0]['analyst_name']
    on_call_email_address = list(
        filter(
            lambda x: x['name'] == on_call_name,
            analysts
        )
    )[0]['email_address']

    return on_call_email_address

def alert_change():
    today = date.today()
    coming_monday = today + timedelta(days=-today.weekday(), weeks=1)

    message = f'Next week\'s On-call person is <@personEmail:{__get_on_call_email_by_monday_date__(coming_monday)}>


def announce_change():
    pass


def who():
    pass


def rotation():
    """get on-call rotation"""
    rotation = get_on_call_details()[1]  # 0 index item is analysts
    now = datetime.now()
    last_to_last_monday = now - timedelta(days=now.weekday() + 7)
    weeks_after_last_to_last_monday = list(
        filter(
            lambda week: datetime.strptime(week['Monday_date'], '%Y-%m-%d') > last_to_last_monday,
            rotation
        )
    )
    return weeks_after_last_to_last_monday
