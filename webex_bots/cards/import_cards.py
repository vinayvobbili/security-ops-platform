"""Adaptive cards for ticket import."""

from webexpythonsdk.models.cards import (
    TextBlock, ColumnSet, Column, AdaptiveCard, HorizontalAlignment,
    Colors, FontWeight, ActionSet, ActionStyle
)
from webexpythonsdk.models.cards.actions import Submit
import webexpythonsdk.models.cards.inputs as INPUTS
import webexpythonsdk.models.cards.options as OPTIONS

TICKET_IMPORT_CARD = AdaptiveCard(
    body=[
        TextBlock(
            text="📥 Import Ticket",
            wrap=True,
            horizontalAlignment=HorizontalAlignment.CENTER,
            weight=FontWeight.BOLDER,
            color=Colors.ACCENT,
        ),
        TextBlock(
            text="🔄 Import an existing ticket from production",
            wrap=True,
            horizontalAlignment=HorizontalAlignment.CENTER,
            isSubtle=True,
        ),
        ColumnSet(
            columns=[
                Column(
                    items=[
                        TextBlock(
                            text="🎫 Prod ticket#",
                            horizontalAlignment=HorizontalAlignment.RIGHT,
                            weight=FontWeight.BOLDER,
                            color=Colors.ACCENT,
                        )
                    ],
                    width=2,
                    verticalContentAlignment=OPTIONS.VerticalContentAlignment.CENTER
                ),
                Column(
                    items=[
                        INPUTS.Text(
                            id="prod_ticket_number",
                            placeholder="Enter prod ticket number",
                            isRequired=True,
                            errorMessage='Required'
                        )
                    ],
                    width=3,
                    verticalContentAlignment=OPTIONS.VerticalContentAlignment.CENTER
                )
            ]
        ),
        ActionSet(
            actions=[
                Submit(
                    title="📥 Import",
                    style=ActionStyle.POSITIVE,
                    data={"callback_keyword": "import"}
                )
            ]
        )
    ]
)
