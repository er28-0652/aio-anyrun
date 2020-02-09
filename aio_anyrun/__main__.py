import click
import logging
import os
import asyncio
import typing as t
from functools import wraps
from uuid import UUID
from getpass import getpass

from aio_anyrun.client import AnyRunClient
from aio_anyrun import const as cst

def is_valid_uuid(ctx, param, value):
    try:
        UUID(value)
    except ValueError:
        raise click.BadParameter(f'Bad UUID, {value}')
    return value

def get_email():
    email = os.environ.get('ANYRUN_EMAIL')
    if email is None:
        email = input('Email: ')
    return email

def get_password():
    password = os.environ.get('ANYRUN_PASSWORD')
    if password is None:
        password = getpass('Password: ')
    return password


def enable_debug_logging():
    logging.basicConfig(
        format='%(asctime)s : %(threadName)s : %(levelname)s : %(message)s',
        level=logging.DEBUG)

def coro(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        return asyncio.run(f(*args, **kwargs))
    return wrapper


@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx):
    if ctx.invoked_subcommand is None:
        print(ctx.get_help())


@cli.command(help='Download file')
@click.option('-u', '--uuid', callback=is_valid_uuid, type=str, required=True, help='UUID for task')
@click.option('-e', '--email', type=str, help='email address for ANY.RUN')
@click.option('-d', '--dest', type=str, default='.', help='path to save file')
@coro
async def download_file(uuid: str, email: str, dest: str):
    # get credentials
    email = email or get_email()
    password = get_password()

    try:
        async with AnyRunClient.connect() as c:
            if not await c.login(email, password):
                raise RuntimeError(f'Login failed.')

            task = await c.get_single_task(uuid)
            if not task.is_downloadable:
                raise ValueError(f'not downloadable. Task(uuid={uuid}, type={task.run_type}, name={task.name})')
            
            saved_path = await c.download_file(task, dest)
            click.echo(f'[*] download success. (Password: infected)\npath:\t{saved_path.absolute()}\nsha1:\t{task.sha1}\nsha256:\t{task.sha256}')
    except Exception as e:
        click.echo(f'[!] download fail. err: {e}')


@cli.command(help='Download pcap')
@click.option('-u', '--uuid', callback=is_valid_uuid, type=str, required=True, help='UUID for task')
@click.option('-e', '--email', type=str, help='email address for ANY.RUN')
@click.option('-d', '--dest', type=str, default='.', help='path to save pcap')
@coro
async def download_pcap(uuid: str, email: str, dest: str):
    # get credentials
    email = email or get_email()
    password = get_password()

    try:
        async with AnyRunClient.connect() as c:
            if not await c.login(email, password):
                raise RuntimeError(f'Login failed.')

            task = await c.get_single_task(uuid)
            saved_path = await c.download_pcap(task, dest)
            click.echo(f'[*] download success.\npath:\t{saved_path.absolute()}')
    except Exception as e:
        click.echo(f'[!] download fail. err: {e}')


@cli.command(help='Search tasks')
@click.option('-h', '--hash', 'hash_', type=str, default='', help='file hash for task to search')
@click.option('-r', '--run-types', 'run_types', type=click.Choice(cst.RUN_TYPES.data_keys()), multiple=True, help='object type of task')
@click.option('-n', '--name', type=str, default='', help='filename or URL to search')
@click.option('-v', '--verdicts', type=click.Choice(cst.VERDICTS.data_keys()), default=None, multiple=True, help='ANY.RUN sandbox result to filter')
@click.option('-e', '--extensions', type=click.Choice(cst.EXTENSIONS.data_keys()), default=None, multiple=True, help='file types to filter')
@click.option('-i', '--ip', type=str, default='', help='ip address to search, this param can search hashes found during analyzing in sandboxs')
@click.option('-d', '--domain', type=str, default='', help='domain name to search, this param can search hashes found during analyzing in sandbox')
@click.option('-f', '--file-hash', type=str, default='', help='file hash to search, this param can search hashes found during analyzing in sandbox')
@click.option('-m', '--mitre-id', type=str, default='', help='MITRE ATT&CK ID to search, only one tag is acceptables')
@click.option('-s', '--suricata-sid', type=str, default='', help='Suricata SID to search')
@click.option('-t', '--tag', type=str, default='', help='tag name to search, only one tag is acceptable')
@click.option('--debug', is_flag=True, default=False, help='enable debug logging')
@coro
async def search(
    hash_: str,
    run_types: t.Tuple[str],
    name: str,
    verdicts: t.Tuple[str],
    extensions: t.Tuple[str],
    ip: str,
    domain: str,
    file_hash: str,
    mitre_id: str,
    suricata_sid: str,
    tag: str,
    debug: bool
):
    if debug:
        enable_debug_logging()

    async with AnyRunClient.connect() as c:
        tasks = await c.search(
            hash_=hash_,
            run_type=run_types,
            name=name,
            verdict=verdicts,
            extensions=extensions,
            ip=ip,
            domain=domain,
            file_hash=file_hash,
            mitre_id=mitre_id,
            tag=tag
        )
        for i, task in enumerate(tasks):
            click.echo(str(i+1).center(20, '='))
            click.echo(f'type:\t\t{task.run_type}')
            click.echo(f'name:\t\t{task.name}')
            click.echo(f'sha1:\t\t{task.sha1}')
            click.echo(f'sha256:\t\t{task.sha256}')
            click.echo(f'verdict:\t{task.verdict}')
            click.echo(f'mime_type:\t{task.mime_type}')
            click.echo(f'task_uuid:\t{task.task_uuid}')
            click.echo()


@cli.command(help='Get IoC information')
@click.option('-u', '--uuid', callback=is_valid_uuid, type=str, required=True, help='UUID for task')
@click.option('-r', '--raw', is_flag=True, help='print raw json output')
@click.option('--debug', is_flag=True, default=False, help='enable debug logging')
@coro
async def get_ioc(uuid: str, raw: bool, debug: bool):
    if debug:
        enable_debug_logging()

    async with AnyRunClient.connect() as c:
        iocs = await c.get_ioc(uuid)
        if raw:
            click.echo(iocs.json())
        else:
            for _, values in iocs.items():
                for value in values:
                    for k, v in value.items():
                        click.echo(f'{k}: {v}')
                    click.echo()


def main():
    cli()


if __name__ == '__main__':
    main()