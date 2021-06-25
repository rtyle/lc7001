"""asyncio (aio) Legrand Adorne LC7001 Hub interface.

https://www.legrand.us/wiring-devices/electrical-accessories/miscellaneous/adorne-hub/p/lc7001
https://www.amazon.com/Legrand-Q-LC7001-Lighting-Controller/dp/B06XW1MLVF

https://www.legrand.us/solutions/smart-lighting/radio-frequency-lighting-controls
https://developer.legrand.com/documentation/rflc-api-for-lc7001/
"""

import abc
import asyncio
import collections
import contextlib
import json
import logging
from typing import Final, Type

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes

_logger: Final = logging.getLogger(__name__)


class _ConnectionContext(contextlib.AbstractAsyncContextManager):
    def __init__(self, host: str, port: int):
        self._host = host
        self._port = port
        self._writer = None

    async def __aenter__(self):
        reader, self._writer = await asyncio.open_connection(self._host, self._port)
        return (reader, self._writer)

    async def __aexit__(self, et, ev, tb):
        if self._writer is not None:
            self._writer.close()
            try:
                await self._writer.wait_closed()
            except OSError:
                pass


class Session:  # pylint: disable=too-few-public-methods
    """Empty successful session."""

    # default arguments
    HOST: Final = "LCM1.local"
    PORT: Final = 2112
    TIMEOUT: Final = 60.0

    @classmethod
    def streamer(
        cls, *args, host: str = HOST, port: int = PORT, timeout: float = TIMEOUT
    ):
        """return _SessionStreamer(host, port, timeout, cls), for this cls of Session."""
        return _SessionStreamer(host, port, timeout, cls, args)

    async def main(self):
        """Connection successful!"""
        return True

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self._reader = reader
        self._writer = writer


class _SessionStreamer:  # pylint: disable=too-few-public-methods
    """Stream sessions (one per connection) and return the result of the first successful one."""

    def session(self):
        """Return the current session, perhaps None."""
        return self._session

    async def main(self):
        """Return the result of the first successful session."""
        while True:
            try:
                async with _ConnectionContext(self._host, self._port) as connection:
                    self._session = self._type(*connection, *self._args)
                    return await self._session.main()
            except EOFError as error:
                _logger.error("EOFError")
            except OSError as error:
                _logger.error("OSError %s", error)
            except asyncio.TimeoutError:
                _logger.error("asyncio.TimeoutError")
            self._session = None
            await asyncio.sleep(self._timeout)

    def __init__(
        self, host: str, port: int, timeout: float, _type: Type[Session], args
    ):
        self._host = host
        self._port = port
        self._timeout = timeout
        self._type = _type
        self._args = args
        self._session = None


class _Sender(Session):  # pylint: disable=too-few-public-methods

    # message keys
    APP_CONTEXT_ID: Final = "AppContextId"  # echoed in reply
    _ID: Final = "ID"  # echoed in reply
    PROPERTY_LIST: Final = "PropertyList"
    SCENE_LIST: Final = "SceneList"
    SERVICE: Final = "Service"
    SID: Final = "SID"  # json_integer, 0-99
    ZID: Final = "ZID"  # json_integer, 0-99
    ZONE_LIST: Final = "ZoneList"

    # PROPERTY_LIST keys
    NAME: Final = "Name"  # json_string, 1-20 characters

    # SCENE PROPERTY_LIST keys
    DAY_BITS: Final = "DayBits"  # json_integer, DAY_BITS values
    DELTA: Final = "Delta"  # json_integer, minutes before or after TRIGGER_TIME
    FREQUENCY: Final = "Frequency"  # json_integer, FREQUENCY values
    SKIP: Final = "Skip"  # json_boolean, True to skip next trigger
    TRIGGER_TIME: Final = "TriggerTime"  # json_integer, time_t
    TRIGGER_TYPE: Final = "TriggerType"  # json_integer, TRIGGER_TYPE values

    # SCENE PROPERTY_LIST, DAY_BITS values
    SUNDAY: Final = 0
    MONDAY: Final = 1
    TUESDAY: Final = 2
    WEDNESDAY: Final = 3
    THURSDAY: Final = 4
    FRIDAY: Final = 5
    SATURDAY: Final = 6

    # SCENE PROPERTY_LIST, FREQUENCY values
    NONE: Final = 0
    ONCE: Final = 1
    WEEKLY: Final = 2

    # SCENE PROPERTY_LIST, TRIGGER_TYPE values
    REGULAR_TIME: Final = 0
    SUNRISE: Final = 1
    SUNSET: Final = 2

    # SCENE PROPERTY_LIST, ZONE_LIST array, item keys (always with ZID)
    LEVEL: Final = "Lvl"  # json_integer, 1-100 (POWER_LEVEL)
    RR: Final = "RR"  # json_integer, 1-100 (RAMP_RATE)
    ST: Final = "St"  # json_boolean, True/False (state toggle?)

    # SYSTEM PROPERTY_LIST keys
    KEYS: Final = "Keys"

    # ZONE PROPERTY_LIST keys
    DEVICE_TYPE: Final = "DeviceType"  # json_string, DIMMER/, reported only
    POWER: Final = "Power"  # json_boolean, True/False
    POWER_LEVEL: Final = "PowerLevel"  # json_integer, 1-100
    RAMP_RATE: Final = "RampRate"  # json_integer, 1-100

    # ZONE PROPERTY_LIST, DEVICE_TYPE values
    DIMMER: Final = "Dimmer"
    SWITCH: Final = "Switch"

    # SERVICE values
    CREATE_SCENE: Final = "CreateScene"
    DELETE_SCENE: Final = "DeleteScene"
    DELETE_ZONE: Final = "DeleteZone"
    LIST_SCENES: Final = "ListScenes"
    LIST_ZONES: Final = "ListZones"
    REPORT_SCENE_PROPERTIES: Final = "ReportSceneProperties"
    REPORT_SYSTEM_PROPERTIES: Final = "ReportSystemProperties"
    REPORT_ZONE_PROPERTIES: Final = "ReportZoneProperties"
    RUN_SCENE: Final = "RunScene"
    SET_SCENE_PROPERTIES: Final = "SetSceneProperties"
    SET_SYSTEM_PROPERTIES: Final = "SetSystemProperties"
    SET_ZONE_PROPERTIES: Final = "SetZoneProperties"
    TRIGGER_RAMP_COMMAND: Final = "TriggerRampCommand"
    TRIGGER_RAMP_ALL_COMMAND: Final = "TriggerRampAllCommand"

    async def send(self, message: dict[str]):
        """Send a composed message."""
        _id = self._id + 1
        message[self._ID] = _id
        self._id = _id
        writer = self._writer
        writer.write(json.dumps(message).encode())
        writer.write(b"\x00")
        await writer.drain()
        _logger.debug("\t< %s", message)

    def compose_list_scenes(self):
        """Compose a LIST_SCENES message."""
        return {self.SERVICE: self.LIST_SCENES}

    def compose_list_zones(self):
        """Compose a LIST_ZONES message."""
        return {self.SERVICE: self.LIST_ZONES}

    def compose_report_scene_properties(self, sid: int):
        """Compose a REPORT_SCENE_PROPERTIES message."""
        return {self.SERVICE: self.REPORT_SCENE_PROPERTIES, self.SID: sid}

    def compose_report_system_properties(self):
        """Compose a REPORT_SYSTEM_PROPERTIES message."""
        return {self.SERVICE: self.REPORT_SYSTEM_PROPERTIES}

    def compose_report_zone_properties(self, zid: int):
        """Compose a REPORT_ZONE_PROPERTIES message."""
        return {self.SERVICE: self.REPORT_ZONE_PROPERTIES, self.ZID: zid}

    def compose_set_zone_properties(
        self, zid: int, name: str = None, power: bool = None, power_level: int = None
    ):
        """Compose a SET_ZONE_PROPERTIES message."""
        property_list = {}
        if name is not None:
            property_list[self.NAME] = name
        if power is not None:
            property_list[self.POWER] = power
        if power_level is not None:
            property_list[self.POWER_LEVEL] = power_level
        return {
            self.SERVICE: self.SET_ZONE_PROPERTIES,
            self.ZID: zid,
            self.PROPERTY_LIST: property_list,
        }

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        super().__init__(reader, writer)
        self._id = 0  # id of last send


class Consumer(_Sender):
    """A Consumer (is also a _Sender) whose messages are handled by an abstract consume method."""

    # default constructor values
    TIMEOUT: Final = 60.0

    # ZONE PROPERTY_LIST keys
    DEVICE_TYPE: Final = "DeviceType"  # json_string, DIMMER/, consume only

    class StatusError(ValueError):
        """StatusError constructed from a message."""

        # message keys
        ERROR_TEXT: Final = "ErrorText"
        ERROR_CODE: Final = "ErrorCode"
        STATUS: Final = "Status"

        # STATUS values
        STATUS_SUCCESS: Final = "Success"
        STATUS_ERROR: Final = "Error"

        def __init__(self, message: dict[str]):
            if self.STATUS in message:
                self.error = message[self.STATUS] != self.STATUS_SUCCESS
            else:
                self.error = True
            if self.ERROR_TEXT in message:
                self.error_text = message[self.ERROR_TEXT]
            if self.ERROR_CODE in message:
                self.error_code = message[self.ERROR_CODE]
                super().__init__(self.error_code)
            else:
                super().__init__()

        def __bool__(self):
            return self.error

        def raise_if(self):
            """Raise self if there was an error."""
            if self:
                raise self

    @abc.abstractmethod
    async def consume(self, message: dict[str]):
        """Consume a message."""

    class _Frames(collections.abc.AsyncIterator):
        def __init__(self, reader: asyncio.StreamReader, timeout):
            self._reader = reader
            self._timeout = timeout

        def __aiter__(self):
            return self

        async def __anext__(self):
            # return null terminated frame, without the terminator
            return (
                await asyncio.wait_for(self._reader.readuntil(b"\x00"), self._timeout)
            )[:-1]

    async def unwrap(self, frame: bytes):
        """Unframe message(s)."""
        try:
            message = json.loads(frame)
        except json.JSONDecodeError as error:
            _logger.error("except json.JSONDecodeError: %s %s", error, frame)
        else:
            await self.consume(message)

    async def main(self):
        async for frame in self._frames:
            _logger.debug("\t> %s", frame.decode())
            await self.unwrap(frame)

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        timeout: float = TIMEOUT,
    ):
        super().__init__(reader, writer)
        self._timeout = timeout
        self._frames = self._Frames(reader, timeout)


class _Inner:  # pylint: disable=too-few-public-methods
    """An _Inner instance remembers its outer instance."""

    def __init__(self, outer):
        self._outer = outer

    def outer(self):
        """Get private _outer attribute."""
        return self._outer


class _EventEmitter:
    """_EventEmitter pattern implementation."""

    class _Once(_Inner):  # pylint: disable=too-few-public-methods
        """_Once is an _Inner class of _EventEmitter that forward an emission once."""

        async def _forward(self, *event):
            self.outer().off(self._name, self._forward)
            if event:
                await self._handler(*event)

        def __init__(self, outer, name: str, handler: collections.abc.Awaitable):
            super().__init__(outer)
            self._name = name
            self._handler = handler
            self.outer().on(self._name, self._forward)

    def __init__(self):
        self._handlers = {}

    def on(
        self, name: str, handler: collections.abc.Awaitable
    ):  # pylint: disable=invalid-name
        """Register the handler for events with this name."""
        if name not in self._handlers:
            self._handlers[name] = [handler]
        else:
            self._handlers[name].append(handler)
        return self

    def off(self, name: str, handler: collections.abc.Awaitable):
        """Unregister the handler for events with this name."""
        if name not in self._handlers:
            raise ValueError(name)
        handlers = self._handlers[name]
        handlers.remove(handler)  # may raise ValueError
        if len(handlers) == 0:
            del self._handlers[name]
        return self

    def once(self, name: str, handler: collections.abc.Awaitable):
        """Register the handler for one event with this name."""
        self._Once(self, name, handler)
        return self

    async def _emit(self, name: str, *event):
        """Emit *event to all handlers for name."""
        if name in self._handlers:
            # iterate over a copy so that a handler may change the handlers
            handlers = self._handlers[name].copy()
            for handler in handlers:
                await handler(*event)
        return self


class Emitter(Consumer, _EventEmitter):
    """Emitter is a Consumer and an _EventEmitter of consumed messages."""

    # events emitted with message
    EVENT_BROADCAST: Final = f"{Consumer._ID}:0"
    EVENT_DELETE_ZONE: Final = f"{Consumer.SERVICE}:{Consumer.DELETE_ZONE}"
    EVENT_LIST_SCENES: Final = f"{Consumer.SERVICE}:{Consumer.LIST_SCENES}"
    EVENT_LIST_ZONES: Final = f"{Consumer.SERVICE}:{Consumer.LIST_ZONES}"
    EVENT_PING: Final = f"{Consumer.SERVICE}:ping"
    EVENT_REPORT_SCENE_PROPERTIES: Final = (
        f"{Consumer.SERVICE}:{Consumer.REPORT_SCENE_PROPERTIES}"
    )
    EVENT_REPORT_SYSTEM_PROPERTIES: Final = (
        f"{Consumer.SERVICE}:{Consumer.REPORT_SYSTEM_PROPERTIES}"
    )
    EVENT_REPORT_ZONE_PROPERTIES: Final = (
        f"{Consumer.SERVICE}:{Consumer.REPORT_ZONE_PROPERTIES}"
    )
    EVENT_RUN_SCENE: Final = f"{Consumer.SERVICE}:{Consumer.RUN_SCENE}"
    EVENT_SET_SCENE_PROPERTIES: Final = (
        f"{Consumer.SERVICE}:{Consumer.SET_SCENE_PROPERTIES}"
    )
    EVENT_SET_SYSTEM_PROPERTIES: Final = (
        f"{Consumer.SERVICE}:{Consumer.SET_SYSTEM_PROPERTIES}"
    )
    EVENT_SET_ZONE_PROPERTIES: Final = (
        f"{Consumer.SERVICE}:{Consumer.SET_ZONE_PROPERTIES}"
    )
    EVENT_SCENE_CREATED: Final = f"{Consumer.SERVICE}:SceneCreated"
    EVENT_SCENE_DELETED: Final = f"{Consumer.SERVICE}:SceneDeleted"
    EVENT_SCENE_PROPERTIES_CHANGED: Final = f"{Consumer.SERVICE}:ScenePropertiesChanged"
    EVENT_SYSTEM_PROPERTIES_CHANGED: Final = (
        f"{Consumer.SERVICE}:SystemPropertiesChanged"
    )
    EVENT_TRIGGER_RAMP_COMMAND: Final = (
        f"{Consumer.SERVICE}:{Consumer.TRIGGER_RAMP_COMMAND}"
    )
    EVENT_TRIGGER_RAMP_ALL_COMMAND: Final = (
        f"{Consumer.SERVICE}:{Consumer.TRIGGER_RAMP_ALL_COMMAND}"
    )
    EVENT_ZONE_ADDED: Final = f"{Consumer.SERVICE}:ZoneAdded"
    EVENT_ZONE_DELETED: Final = f"{Consumer.SERVICE}:ZoneDeleted"
    EVENT_ZONE_PROPERTIES_CHANGED: Final = f"{Consumer.SERVICE}:ZonePropertiesChanged"

    async def consume(self, message: dict[str]):
        if self._ID in message:
            _id = message[self._ID]
            if _id != 0:
                # emit what we consumed (nothing) until caught up.
                # such will be squelched in _EventEmitter.Once but give it a chance to turn off.
                while self._emit_id < _id:
                    await self._emit(f"ID:{self._emit_id}")
                    self._emit_id += 1
            await self._emit(f"ID:{_id}", message)
        if self.SERVICE in message:
            _service = message[self.SERVICE]
            await self._emit(f"{self.SERVICE}:{_service}", message)

    async def handle_send(self, handler: collections.abc.Awaitable, message: dict[str]):
        """Handle the response from send(message)."""
        self.once(f"{self._ID}:{self._id + 1}", handler)
        await self.send(message)

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        timeout: float = Consumer.TIMEOUT,
    ):
        Consumer.__init__(self, reader, writer, timeout)
        _EventEmitter.__init__(self)
        self._emit_id = 1  # id of next emit


class Authenticator(Emitter):  # pylint: disable=too-few-public-methods
    """An Authenticator session runs for the first/authentication phase only.

    This phase will either end by exception or a (success: bool, address: bytes) result.
    If the phase ended with a SETKEY response, the StatusError formed from the response
    will be appended.
    """

    # Security message prefixes
    SECURITY_MAC: Final = b'{"MAC":'
    SECURITY_HELLO: Final = b"Hello V1 "
    SECURITY_HELLO_INVALID: Final = b"[INVALID]"
    SECURITY_HELLO_OK: Final = b"[OK]"
    SECURITY_SETKEY: Final = b"[SETKEY]"

    # SECURITY_HELLO key
    MAC: Final = "MAC"

    # even though the API will allow passwords less than 8 characters,
    # the APP will not
    PASSWORD: Final = b"........"

    @staticmethod
    def _hash(data: bytes) -> bytes:
        digest = hashes.Hash(hashes.MD5())
        digest.update(data)
        return digest.finalize()

    @staticmethod
    def _encrypt(key: bytes, data: bytes) -> bytes:
        cipher = Cipher(algorithms.AES(key), modes.ECB())
        encryptor = cipher.encryptor()
        return encryptor.update(data) + encryptor.finalize()

    class _Result(StopAsyncIteration):
        pass

    async def send_challenge_response(self, key: bytes, challenge: bytes):
        """Send a challenge response (the AES(key) encryption of challenge)."""
        message = self._encrypt(key, challenge).hex()
        writer = self._writer
        writer.write(message.encode())
        await writer.drain()
        _logger.debug("\t< %s", message)

    def compose_keys(self, old: bytes, new: bytes):
        """Compose a SET_SYSTEM_PROPERTIES message with KEYS made from old and new."""
        return {
            self.SERVICE: self.SET_SYSTEM_PROPERTIES,
            self.PROPERTY_LIST: {
                self.KEYS: "".join(
                    [self._encrypt(old, key).hex() for key in (old, new)]
                )
            },
        }

    async def _consume_security_setkey(self):
        """Consume a SECURITY_SETKEY message."""
        # } terminated json encoding
        frame = await asyncio.wait_for(self._reader.readuntil(b"}"), self._timeout)
        try:
            message = json.loads(frame)
        except json.JSONDecodeError as error:
            _logger.error("except json.JSONDecodeError: %s %s", error, frame)
        else:
            self._address = message[self.MAC]

            async def handle(message: dict[str]):
                _logger.info("%s", message)
                error = self.StatusError(message)
                raise self._Result(bool(error), self._address, error)

            await self.handle_send(
                handle, self.compose_keys(self._hash(b""), self._key)
            )

    async def _consume_security_hello(self):
        """Consume a SECURITY_HELLO message."""
        # space terminated challenge phrase
        challenge = (
            await asyncio.wait_for(self._reader.readuntil(b" "), self._timeout)
        )[:-1]
        _logger.debug("\t>\t%s", challenge.decode())
        # 12 byte MAC address
        self._address = await asyncio.wait_for(
            self._reader.readexactly(12), self._timeout
        )
        _logger.debug("\t>\t%s", self._address.decode())
        await self.send_challenge_response(self._key, bytes.fromhex(challenge.decode()))

    def _consume_security_hello_response(self, success: bool):
        """Consume SECURITY_OK/SECURITY_INVALID message from challenge response."""
        raise self._Result(success, self._address)

    def _consume_security_mac(self, message):
        raise self._Result(True, message[self.MAC])

    def _unwrap_security_mac(self, frame):
        try:
            message = json.loads(frame)
            self._consume_security_mac(message)
        except json.JSONDecodeError as error:
            # this frame may have another JSON encoded message packed in it. cut ours out.
            try:
                cut = frame[: frame.rindex(b"{")]
                message = json.loads(cut)
                self._consume_security_mac(message)
            except json.JSONDecodeError as error:
                _logger.error("except json.JSONDecodeError: %s %s", error, cut)

    async def unwrap(self, frame: bytes):
        if frame.startswith(self.SECURITY_MAC):
            self._unwrap_security_mac(frame)
        # elif frame.startswith(self.SECURITY_SETKEY):
        #     await self._consume_security_setkey()
        # elif frame.startswith(self.SECURITY_HELLO):
        #     await self._consume_security_hello()
        # elif frame.startswith(self.SECURITY_HELLO_OK):
        #     await self._consume_security_hello_response(True)
        # elif frame.startswith(self.SECURITY_HELLO_INVALID):
        #     self._consume_security_hello_response(False)
        else:
            await super().unwrap(frame)

    async def main(self):
        try:
            await super().main()
        except self._Result as result:
            return result.args

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        timeout: float = Consumer.TIMEOUT,
    ):
        super().__init__(reader, writer, timeout)
        self._key = self._hash(self.PASSWORD)
        self._address = None
