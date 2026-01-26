"""Adaptive cards for tuning requests."""

from webexpythonsdk.models.cards import (
    TextBlock, AdaptiveCard, HorizontalAlignment,
    Colors, FontWeight, ActionSet, ActionStyle
)
from webexpythonsdk.models.cards.actions import Submit
import webexpythonsdk.models.cards.inputs as INPUTS

TUNING_REQUEST_CARD = AdaptiveCard(
    body=[
        TextBlock(
            text="🔧 New Tuning Request",
            wrap=True,
            horizontalAlignment=HorizontalAlignment.CENTER,
            weight=FontWeight.BOLDER,
            color=Colors.ACCENT,
        ),
        TextBlock(
            text="⚙️ Submit a request to fine-tune detection rules",
            wrap=True,
            horizontalAlignment=HorizontalAlignment.CENTER,
            isSubtle=True,
        ),
        INPUTS.Text(
            id="title",
            label="📝 Title",
            isRequired=True,
            errorMessage="Required",
            placeholder="Enter tuning request title"
        ),
        INPUTS.Text(
            id="description",
            label="📋 Description",
            isMultiline=True,
            isRequired=True,
            errorMessage="Required",
            placeholder="Describe the tuning needed"
        ),
        INPUTS.Text(
            id="tickets",
            placeholder="A few recent X tix created by this rule",
            label="🎫 X ticket(s)",
            isRequired=True,
            errorMessage="Required"
        ),
        INPUTS.Text(
            id="ticket_volume",
            placeholder="Example: 10 tickets/week",
            label="📊 Approx. Ticket Volume",
            isRequired=True,
            errorMessage="Required"
        ),
        ActionSet(
            actions=[
                Submit(
                    title="🚀 Submit Request",
                    style=ActionStyle.POSITIVE,
                    data={"callback_keyword": "tuning_request"}
                )
            ],
        )
    ]
)
