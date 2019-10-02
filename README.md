# My Scripts

pcidss-fortune: PCIDSS quotes for the Linux command "fortune", formatted to send to slack via a webhook, in a crontab like this ...

0  9  *  *  * root curl -X POST --data-urlencode "payload={\"channel\": \"#CHANNEL_NAME\", \"username\": \"PCIDSS says\", \"text\": $(fortune pcidss | python -c "import json,sys; print(json.dumps(sys.stdin.read()))"), \"icon_emoji\": \":pci:\"}" https://hooks.slack.com/WEBHOOK_ID
