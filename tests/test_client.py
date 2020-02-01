try:
    from unittest import IsolatedAsyncioTestCase as AsyncTestCase
except ImportError:
    from aiounittest import AsyncTestCase

from aio_anyrun import client

TESTS_FOR_SINGLE_TASK = {
    '640a15a3-7b2c-4b84-ab4a-fde92f409455': 'f942e141f11540a1a3a387fad48df8329f46d4d8',
    'acdcbcf3-4b3a-42ca-aae5-736683b86800': '96a2558e0fbc103907c6aa119e85598d30ad330a',
    '08d7c9ed-df02-403f-b07d-3ceb9f1ba05f': '7f8dfc4d5d8740dae6a98fe0de08fc6589aafe39'
}


class TestAnyRunClient(AsyncTestCase):

    async def test_get_public_tasks(self):
        c = client.AnyRunClient()
        await c.init_connection_with_default_client()
        tasks = await c.get_public_tasks()
        self.assertEqual(50, len(tasks))
        await c.close()
    
    async def test_get_single_task(self):
        c = client.AnyRunClient()
        await c.init_connection_with_default_client()
        for task_uuid, expect in TESTS_FOR_SINGLE_TASK.items():
            task = await c.get_single_task(task_uuid)
            self.assertEqual(task.sha1, expect)
        await c.close()

    async def test_get_single_task_contextmanager(self):
        async with client.AnyRunClient.connect() as c:
            for task_uuid, expect in TESTS_FOR_SINGLE_TASK.items():
                task = await c.get_single_task(task_uuid)
                self.assertEqual(task.sha1, expect)

    async def test_get_public_tasks_contextmanager(self):
        async with client.AnyRunClient.connect() as c:
            tasks = await c.get_public_tasks()
            self.assertEqual(50, len(tasks))
    