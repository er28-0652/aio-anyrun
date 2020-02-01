[![Actions Status](https://github.com/er28-0652/aio-anyrun/workflows/Main%20workflow/badge.svg)](https://github.com/er28-0652/aio-anyrun/actions)

# aio-anyrun

Asynchronous python client of [ANY.RUN](https://app.any.run/) using unofficial API.

## Requirement
* python >= 3.8

## Usage

### Basic Usage
connect with contextmanager

```python
from aio_anyrun.client import AnyRunClient

async with AnyRunClient.connect() as client:
    if client.login('<YOUR_EMAIL_ADDRESS>', '<YOUR_PASSWORD>'):
        tasks = await client.get_public_tasks()
        for task in tasks:
            if task.is_downloadable:
                saved_path = client.dowload_file(task)
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