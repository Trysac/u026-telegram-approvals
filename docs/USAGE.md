# Usage

```python
from datetime import datetime, timezone

from telegram_approvals import ApprovalQueue
from telegram_approvals.testing import FakeTransport

transport = FakeTransport()
queue = ApprovalQueue(
    transport, 1, frozenset({42}), bytes(range(32)), lambda: datetime.now(timezone.utc)
)
queue.request("deploy", "v2")
data = transport.sent[0].buttons[0][1]
print(queue.handle_callback("q1", data, 42).state)
```

Implement `TelegramTransport` (`send_message`, `edit_message`, `answer_callback`) on top of your
Bot API client for production. Feed `callback_query.id`, `callback_query.data` and
`callback_query.from.id` to `handle_callback`, and call `expire_due()` periodically.
