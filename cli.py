"""Command Line Interpreter to interact with LC7001 HOSTs

Run with --help to see command line usage.

This code serves as a demonstration of expected lc7001.aio usage:

There will be some type(s) of Adaptor(s) to add behavior beyond that of an
lc7001.aio.Authenticator (which is a message Emitter, Consumer and Sender).
Here, our _Adapter does nothing more than be an Authenticator and then an Emitter.
With DEBUG turned on, the messages passed in (>) to us and out (<) from us are logged.
This is a great way to demonstrate the LC7001 behavior.

There will be some type(s) of Interpreter(s) that will need to interact with LC7001 HOSTs.
Here, our _Interpreter takes lines from STDIN, composes messages from them and sends them to
(through the current session with) the currently targeted HOST.

The STDIN commands are:

            -- a blank line sends a REPORT_SYSTEM_PROPERTIES message

h           -- target the next HOST in rotation (start with first HOST)

q           -- quit

s           -- send a LIST_SCENES message
s *         -- send a LIST_SCENES message then a REPORT_SCENE_PROPERTIES for each listed
s SID       -- send a REPORT_SCENE_PROPERTIES message for SID (0-99)

z           -- send a LIST_ZONES message
z *         -- send a LIST_ZONES message then a REPORT_ZONE_PROPERTIES for each listed
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


class _Adapter(lc7001.aio.Authenticator):
    async def main(self):
        authenticated = await super().main()
        _logger.debug(authenticated)
        await lc7001.aio.Emitter.main(self)
        _logger.debug("main exit")


class _Interpreter:  # pylint: disable=too-few-public-methods
    @staticmethod
    async def _stdio():
        reader = asyncio.StreamReader()
        reader_protocol = asyncio.StreamReaderProtocol(reader)
        loop = asyncio.get_event_loop()
        writer_transport, writer_protocol = await loop.connect_write_pipe(
            asyncio.streams.FlowControlMixin, os.fdopen(1, "wb")
        )
        writer = asyncio.StreamWriter(writer_transport, writer_protocol, None, loop)
        await loop.connect_read_pipe(lambda: reader_protocol, sys.stdin)
        return reader, writer

    async def _command_scene(self, session, token):
        try:
            sid = next(token)
        except StopIteration:
            await session.send(session.compose_list_scenes())
        else:
            if sid == "*":

                async def handle(message):
                    lc7001.aio.Consumer.StatusError(message).raise_if()
                    for item in message[session.SCENE_LIST]:
                        await session.send(
                            session.compose_report_scene_properties(item[session.SID])
                        )

                await session.handle_send(handle, session.compose_list_scenes())
            else:
                await session.send(session.compose_report_scene_properties(int(sid)))

    async def _command_zone(self, session, token):
        try:
            zid = next(token)
        except StopIteration:
            await session.send(session.compose_list_zones())
        else:
            if zid == "*":

                async def handle(message):
                    lc7001.aio.Consumer.StatusError(message).raise_if()
                    for item in message[session.ZONE_LIST]:
                        await session.send(
                            session.compose_report_zone_properties(item[session.ZID])
                        )

                await session.handle_send(handle, session.compose_list_zones())
            else:
                try:
                    value = int(next(token))
                except StopIteration:
                    await session.send(session.compose_report_zone_properties(int(zid)))
                else:
                    if value < 2:
                        await session.send(
                            session.compose_set_zone_properties(
                                int(zid), power=bool(value)
                            )
                        )
                    else:
                        await session.send(
                            session.compose_set_zone_properties(
                                int(zid), power_level=value - 1
                            )
                        )

    async def _command(self, session, line: str):
        token = iter(line.decode().strip().split())
        try:
            command = next(token)
        except StopIteration:
            await session.send(session.compose_report_system_properties())
        else:
            if command.startswith("h"):
                self._host += 1
                self._host %= len(self._hosts)
                _logger.info("host %s", self._hosts[self._host])
            elif command.startswith("q"):
                return True
            elif command.startswith("s"):
                await self._command_scene(session, token)
            elif command.startswith("z"):
                await self._command_zone(session, token)

    async def main(self):
        """Translate commands from STDIN, through current session, to selected host."""
        reader, _ = await self._stdio()
        while True:
            line = await reader.readline()
            if len(line) == 0:
                break
            session = self._streamers[self._host].session()
            if session is None:
                _logger.error("%s not in session", self._hosts[self._host])
                continue
            await self._command(session, line)

    def __init__(self, hosts: Sequence[str], streamers: Sequence):
        self._streamers = streamers
        self._hosts = hosts
        self._host = 0


class _Main:  # pylint: disable=too-few-public-methods
    async def _main(self):
        streamers = [
            _Adapter.streamer(lc7001.aio.Consumer.TIMEOUT, self._key, host=host)
            for host in self._hosts
        ]
        interactor = _Interpreter(self._hosts, streamers)

        async def _run(streamer):
            await streamer.main()

        await asyncio.gather(
            interactor.main(), *(_run(streamer) for streamer in streamers)
        )

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
HOST: Final = lc7001.aio.Session.HOST
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
    default=HOST,
    help=f"resolves to LC7001 IP address (default {HOST})",
)
args = parser.parse_args()

_Main(lc7001.aio.Authenticator.hash(args.password.encode()), args.hosts)
