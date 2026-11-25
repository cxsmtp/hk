# Get help: support cases and enhancements

Anyone signed in can ask for help or for something new, get a number by email, and follow it until it is done. The support team answers in the same place. Ported from CxMissionZero's docs/support.md; the page is **Get help** (`/help`), laid out as FTR Command Center's.

## Asking

On **Get help**, choose **Something is not working** (a support case, with how urgent it is: Low, Normal, High, or Urgent when work is blocked) or **I would like something added or changed** (an enhancement). Cases are numbered SUP-0001, SUP-0002 and so on; enhancements ENH-0001, ENH-0002. As soon as you send, the page shows your number, and you get an email with it and a link to follow the request.

## Following a request

The list below the form shows your requests, newest first. Click one to read its conversation, its status, and the history of status changes, and to add to it: the support team gets an email. When the team answers or changes the status, you get an email too.

| Status | Meaning |
| --- | --- |
| New | Raised, not picked up yet |
| In progress | The team is working on it |
| Waiting for reply | The team needs something from you. Answering sends it back to them as In progress |
| Completed | Done. For an enhancement, it is built |
| Declined | Will not be done. The conversation says why |

Answering a completed or declined request reopens it as New.

## The support team

The owners and admins of the organisation a request was raised in are its support team (CxMissionZero's "Answer support cases & enhancements"). They see every request raised in it (**Mine** narrows the list to their own), get an email for every new request and every answer from the person who raised it, answer in the conversation, and move each request on with **Status → Update status**. Everyone else sees only their own requests; opening anyone else's answers "No such request, or it is not yours to see.".

## Email

Emails go through the email server (`SMTP_*`), which must be tested first (Settings → Sign-in, **Send a test email**). The link in each email uses the server's address (`PUBLIC_URL`). If the email server is not set up or not tested, the request is still saved and numbered, and the page says that the email could not be sent, and why.

## Support by email instead (offline installations)

Under **Settings → Get help** (`/settings/help`, owners and admins), Get help can be switched to **Email**, with **Send requests to**. Then sending opens each person's own email app, addressed there, with a subject and a short template ending in who is asking, the Hawk AI version, the organisation and the server address. Nothing is stored in Hawk AI. Until a valid address is entered, Get help stays on the portal. `SUPPORT_MODE=email` and `SUPPORT_EMAIL=support@company.com` set the default when the server starts; a choice made on the page wins over them.

## Limits and storage

- A title can be up to 200 characters, and each message up to 10,000; a conversation holds up to 500 messages.
- One person can raise up to 20 requests an hour.
- Requests are kept in the database (`support_tickets`), so in every backup. Each new request, status change and change of Settings → Get help is in the audit log.
