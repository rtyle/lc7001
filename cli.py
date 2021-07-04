"""Command Line Interpreter to interact with LC7001 HOSTs

Run with --help to see command line usage.

This code serves as a demonstration of expected lc7001.aio usage:

There will be some type(s) of Hub(s) to add behavior beyond that of a
Connector (which is a message Authenticator, Emitter, Consumer and Sender).
Here, we use Hub which does nothing more than be an Authenticator
and then an Emitter for each connection/session.
With DEBUG turned on, the messages passed in (>) to us
and out (<) from us are logged.
This is a great way to demonstrate the LC7001 behavior.

There will be some type(s) of Interpreter(s) that will need to interact
with LC7001 HOSTs.
Here, our _Interpreter takes lines from STDIN, composes messages from them
and sends them to (through the current session with)
the currently targeted HOST.

The STDIN commands are:

            -- a blank line sends a REPORT_SYSTEM_PROPERTIES message

h           -- target the next HOST in rotation (start with first HOST)

q           -- quit

s           -- send a LIST_SCENES message
s *         -- send a LIST_SCENES then a REPORT_SCENE_PROPERTIES for each
s SID       -- send a REPORT_SCENE_PROPERTIES message for SID (0-99)

z           -- send a LIST_ZONES message
z *         -- send a LIST_ZONES then a REPORT_ZONE_PROPERTIES for each
z ZID       -- send a REPORT_ZONE_PROPERTIES message for ZID (0-99)
z ZID 0|1   -- send a SET_ZONE_PROPERTIES message with POWER as False|True
z ZID #     -- send a SET_ZONE_PROPERTIES message with POWER_LEVEL as # - 1
"""

import argparse
import asyncio
import logging
import os
import sys
from typing import Final, Sequence

import lc7001.aio

_module = sys.modules[__name__]
_logger = logging.getLogger(__name__)

logging.basicConfig(level=logging.DEBUG)


class _Interpreter:  # pylint: disable=too-few-public-methods
    @staticmethod
    async def _stdio():
        reader = asyncio.StreamReader()
        reader_protocol = asyncio.StreamReaderProtocol(reader)
        loop = asyncio.get_event_loop()
        writer_transport, writer_protocol = await loop.connect_write_pipe(
            asyncio.streams.FlowControlMixin, os.fdopen(1, "wb")
        )
        writer = asyncio.StreamWriter(
            writer_transport, writer_protocol, None, loop
        )
        await loop.connect_read_pipe(lambda: reader_protocol, sys.stdin)
        return reader, writer

    async def _command_scene(self, hub, token):
        try:
            sid = next(token)
        except StopIteration:
            await hub.send(hub.compose_list_scenes())
        else:
            if sid == "*":

                async def handle(message):
                    lc7001.aio.Consumer.StatusError(message).raise_if()
                    for item in message[hub.SCENE_LIST]:
                        await hub.send(
                            hub.compose_report_scene_properties(item[hub.SID])
                        )

                await hub.handle_send(handle, hub.compose_list_scenes())
            else:
                await hub.send(hub.compose_report_scene_properties(int(sid)))

    async def _command_zone(self, hub, token):
        try:
            zid = next(token)
        except StopIteration:
            await hub.send(hub.compose_list_zones())
        else:
            if zid == "*":

                async def handle(message):
                    lc7001.aio.Consumer.StatusError(message).raise_if()
                    for item in message[hub.ZONE_LIST]:
                        await hub.send(
                            hub.compose_report_zone_properties(item[hub.ZID])
                        )

                await hub.handle_send(handle, hub.compose_list_zones())
            else:
                try:
                    value = int(next(token))
                except StopIteration:
                    await hub.send(
                        hub.compose_report_zone_properties(int(zid))
                    )
                else:
                    if value < 2:
                        await hub.send(
                            hub.compose_set_zone_properties(
                                int(zid), power=bool(value)
                            )
                        )
                    else:
                        await hub.send(
                            hub.compose_set_zone_properties(
                                int(zid), power_level=value - 1
                            )
                        )

    async def _command(self, hub, line: bytes):
        token = iter(line.decode().strip().split())
        try:
            command = next(token)
        except StopIteration:
            await hub.send(hub.compose_report_system_properties())
        else:
            if command.startswith("h"):
                self._host += 1
                self._host %= len(self._hosts)
                _logger.info("host %s", self._hosts[self._host])
            elif command.startswith("s"):
                await self._command_scene(hub, token)
            elif command.startswith("z"):
                await self._command_zone(hub, token)

    async def main(self):
        """Interpret commands from STDIN to hub of selected host."""
        reader, _ = await self._stdio()
        while True:
            line = await reader.readline()
            if len(line) == 0 or line.startswith(b"q"):
                for hub in self._hubs:
                    hub.cancel()
                raise asyncio.CancelledError
            await self._command(self._hubs[self._host], line)

    def __init__(self, hosts: Sequence[str], hubs: Sequence):
        self._hubs = hubs
        self._hosts = hosts
        self._host = 0


class _Main:  # pylint: disable=too-few-public-methods
    async def _main(self):
        hubs = [lc7001.aio.Hub(host, key=self._key) for host in self._hosts]
        interpreter = _Interpreter(self._hosts, hubs)

        await asyncio.gather(interpreter.main(), *(hub.loop() for hub in hubs))

    def __init__(self, key, *hosts):
        self._key = key
        self._hosts = hosts
        try:
            asyncio.run(self._main())
        except asyncio.CancelledError:
            pass
        except KeyboardInterrupt:
            pass


parser = argparse.ArgumentParser(
    description="Command Line Interpreter to interact with LC7001 HOSTs"
)
HOSTS: Final = [lc7001.aio.Connector.HOST]
PASSWORD: Final = lc7001.aio.Authenticator.PASSWORD
parser.add_argument(
    "--password",
    metavar="PASSWORD",
    type=str,
    nargs=1,
    default=PASSWORD,
    help=f"""password for each HOST (default {PASSWORD}
    minimum 8 characters for Legrand Lighting Control App compatibility)""",
)
parser.add_argument(
    "hosts",
    metavar="HOST",
    type=str,
    nargs="*",
    default=HOSTS,
    help=f"resolves to LC7001 IP address (default {HOSTS[0]})",
)
args = parser.parse_args()
_Main(lc7001.aio.hash_password(args.password.encode()), *args.hosts)
