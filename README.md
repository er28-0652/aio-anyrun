# aio-anyrun

Asynchronous python client of [ANY.RUN](https://app.any.run/) using unofficial API.

## Usage

### Basic Usage
connect with contextmanager

```python
from aio_anyrun.client import AnyRunClient

async with AnyRunClient.connect() as client:
    if client.login('<YOUR_EMAIL_ADDRESS>', '<YOUR_PASSWORD>'):
        tasks = await client.get_public_tasks()
        for task in tasks:
            if task.run_type != 'url':
                saved_path = client.dowload_file(task)
```

connect by your self (close connection by yourself)

```python
from aio_anyrun.client import AnyRunClient

client = AnyRunClient()
await client.init_connection_with_default_client()
tasks = await client.get_public_tasks()
await client.close()
```

### Search
Search malicious MS Executable files.
```python
from aio_anyrun.client import AnyRunClient

async with AnyRunClient.connect() as client:
    tasks = await client.search(
        run_type='file',
        verdict='malicious',
        extensions=['exe', 'dll']
    )
```

Search any Office document file with `macros` tag.
```python
from aio_anyrun.client import AnyRunClient

async with AnyRunClient.connect() as client:
    tasks = await client.search(
        run_type='file',
        extensions='office',
        tag='macros'
    )
```

Search any URL with `opendir` tag.
```python
from aio_anyrun.client import AnyRunClient

async with AnyRunClient.connect() as client:
    tasks = await client.search(
        run_type='url',
        tag='opendir'
    )
```