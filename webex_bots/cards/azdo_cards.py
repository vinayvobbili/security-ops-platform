"""Adaptive cards for Azure DevOps work items."""

AZDO_CARD = {
    "type": "AdaptiveCard",
    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
    "version": "1.3",
    "body": [
        {
            "type": "TextBlock",
            "text": "💼 New AZDO Work Item",
            "horizontalAlignment": "Center",
            "weight": "Bolder",
            "size": "Large",
            "color": "Accent"
        },
        {
            "type": "TextBlock",
            "text": "📊 Create and track work items in Azure DevOps",
            "wrap": True,
            "horizontalAlignment": "Center",
            "isSubtle": True,
            "spacing": "Small"
        },
        {
            "type": "Container",
            "style": "emphasis",
            "spacing": "Medium",
            "items": [
                {
                    "type": "TextBlock",
                    "text": "📝 Title",
                    "color": "Accent",
                    "weight": "Bolder"
                },
                {
                    "type": "Input.Text",
                    "wrap": True,
                    "id": "wit_title",
                    "placeholder": "Enter work item title"
                },
                {
                    "type": "TextBlock",
                    "text": "📋 Description",
                    "color": "Accent",
                    "weight": "Bolder",
                    "spacing": "Medium"
                },
                {
                    "type": "Input.Text",
                    "wrap": True,
                    "id": "wit_description",
                    "isMultiline": True,
                    "placeholder": "Describe the work item"
                },
                {
                    "type": "ColumnSet",
                    "spacing": "Medium",
                    "columns": [
                        {
                            "type": "Column",
                            "width": "stretch",
                            "items": [
                                {
                                    "type": "TextBlock",
                                    "text": "🏷️ Type",
                                    "color": "Accent",
                                    "weight": "Bolder"
                                },
                                {
                                    "type": "Input.ChoiceSet",
                                    "wrap": True,
                                    "id": "wit_type",
                                    "choices": [
                                        {"title": "📖 User Story", "value": "User%20Story"},
                                        {"title": "🐛 Bug", "value": "Bug"},
                                        {"title": "✅ Task", "value": "Task"}
                                    ]
                                }
                            ]
                        },
                        {
                            "type": "Column",
                            "width": "stretch",
                            "items": [
                                {
                                    "type": "TextBlock",
                                    "text": "📁 Project",
                                    "color": "Accent",
                                    "weight": "Bolder"
                                },
                                {
                                    "type": "Input.ChoiceSet",
                                    "wrap": True,
                                    "id": "project",
                                    "choices": [
                                        {"title": "Cyber Platforms", "value": "platforms"},
                                        {"title": "Resp Engg Automation", "value": "rea"},
                                        {"title": "Resp Engg Operations", "value": "reo"},
                                        {"title": "Detection Engineering", "value": "de"},
                                        {"title": "GDR Shared", "value": "gdr"}
                                    ]
                                }
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "type": "ActionSet",
            "spacing": "Medium",
            "actions": [
                {
                    "type": "Action.Submit",
                    "title": "🚀 Create",
                    "data": {
                        "callback_keyword": "azdo_wit"
                    },
                    "style": "positive"
                }
            ],
            "horizontalAlignment": "Right"
        }
    ]
}
