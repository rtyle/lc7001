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
import time
from typing import Final

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes

_logger: Final = logging.getLogger(__name__)


class _Sender:

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
        """Send a composed message with the next ID."""
        writer = self._writer
        if writer is None:
            _logger.error("\t<!\t%s", message)
        else:
            _id = self._id + 1
            message[self._ID] = _id
            self._id = _id
            writer.write(json.dumps(message).encode())
            writer.write(b"\x00")
            await writer.drain()
            _logger.debug("\t<\t%s", message)

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

    def __init__(self, writer: asyncio.StreamWriter = None):
        self._writer = writer
        self._id = 0  # id of last send


class _Inner:  # pylint: disable=too-few-public-methods
    """An _Inner instance remembers its outer instance."""

    def __init__(self, outer):
        self._outer = outer

    def outer(self):
        """Get private _outer attribute."""
        return self._outer


class Consumer(_Sender):
    """A Consumer (is also a _Sender) whose messages are handled by an abstract consume method."""

    # default constructor values
    READ_TIMEOUT: Final = 20.0  # expect ping every 5 seconds

    # ZONE PROPERTY_LIST keys
    DEVICE_TYPE: Final = "DeviceType"  # json_string, DIMMER/, consume only

    class StatusError(ValueError):
        """StatusError whose args are derived from a message.

        Returns (error: bool, code: int = 0, text: str = None)
        where error is True if STATUS is not STATUS_SUCCESS,
        code is ERROR_CODE value (or 0) and text is ERROR_TEXT value (or None)."""

        # message keys
        ERROR_TEXT: Final = "ErrorText"
        ERROR_CODE: Final = "ErrorCode"
        STATUS: Final = "Status"

        # STATUS values
        STATUS_SUCCESS: Final = "Success"
        STATUS_ERROR: Final = "Error"

        def __init__(self, message: dict[str]):
            super().__init__(
                message.get(self.STATUS, self.STATUS_ERROR) != self.STATUS_SUCCESS,
                int(message.get(self.ERROR_CODE, "0")),
                message.get(self.ERROR_TEXT, None),
            )

        def __bool__(self):
            return bool(self.args[0])

        def raise_if(self):
            """raise self if bool(self)."""
            if bool(self):
                raise self

    @abc.abstractmethod
    async def consume(self, message: dict[str]):
        """Consume a message."""

    class _Frames(_Inner, collections.abc.AsyncIterator):
        def __aiter__(self):
            return self

        async def __anext__(self):
            # return null terminated frame, without the terminator
            return (
                await asyncio.wait_for(
                    self.outer()._reader.readuntil(b"\x00"), self.outer()._read_timeout
                )
            )[:-1]

    async def unwrap(self, frame: bytes):
        """Unwrap message in frame and consume it."""
        try:
            message = json.loads(frame)
        except json.JSONDecodeError as error:
            _logger.error("except json.JSONDecodeError: %s %s", error, frame)
        else:
            await self.consume(message)

    async def session(self):
        """Iterate over read frames forever."""
        async for frame in self._frames:
            _logger.debug("\t>\t%s", frame.decode())
            await self.unwrap(frame)

    def __init__(
        self,
        read_timeout: float = READ_TIMEOUT,
        reader: asyncio.StreamReader = None,
        writer: asyncio.StreamWriter = None,
    ):
        self._read_timeout = read_timeout
        self._reader = reader
        super().__init__(writer)
        self._frames = self._Frames(self)


class _EventEmitter:
    """_EventEmitter pattern implementation."""

    class _Once(_Inner):  # pylint: disable=too-few-public-methods
        """_Once is an _Inner class of _EventEmitter that forwards an emission once."""

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
            service = message[self.SERVICE]
            await self._emit(f"{self.SERVICE}:{service}", message)
            if self.ZID in message:
                zid = message[self.ZID]
                await self._emit(f"{self.SERVICE}:{service}:{zid}", message)

    async def handle_send(self, handler: collections.abc.Awaitable, message: dict[str]):
        """Handle the response from the message we will send."""
        self.once(f"{self._ID}:{self._id + 1}", handler)
        await self.send(message)

    def __init__(
        self,
        read_timeout: float = Consumer.READ_TIMEOUT,
        reader: asyncio.StreamReader = None,
        writer: asyncio.StreamWriter = None,
    ):
        Consumer.__init__(self, read_timeout, reader, writer)
        _EventEmitter.__init__(self)
        self._emit_id = 1  # id of next emit


class Authenticator(Emitter):  # pylint: disable=too-few-public-methods
    """An Authenticator session runs for the first/authentication phase only.

    This phase will either end by exception (Authentication.Error)
    or the MAC address of the unit that we successfully authenticated with.
    """

    # default constructor values
    # the Legrand Lighting Control App insists on 8 character minimum passwords
    PASSWORD: Final = "........"
    KEY: Final = hash(PASSWORD.encode())

    # Security message prefixes
    SECURITY_MAC: Final = b'{"MAC":'
    SECURITY_HELLO: Final = b"Hello V1 "
    SECURITY_HELLO_INVALID: Final = b"[INVALID]"
    SECURITY_HELLO_OK: Final = b"[OK]"
    SECURITY_SETKEY: Final = b"[SETKEY]"

    # SYSTEM PROPERTY_LIST keys
    KEYS: Final = "Keys"

    # SECURITY_MAC and SECURITY_SETKEY key
    MAC: Final = "MAC"

    @staticmethod
    def hash(data: bytes) -> bytes:
        """Return a hash from data, suitable for turning a password into an encryption key."""
        digest = hashes.Hash(hashes.MD5())
        digest.update(data)
        return digest.finalize()

    @staticmethod
    def _encrypt(key: bytes, data: bytes) -> bytes:
        cipher = Cipher(algorithms.AES(key), modes.ECB())
        encryptor = cipher.encryptor()
        return encryptor.update(data) + encryptor.finalize()

    class Error(ValueError):
        """Authentication error."""

    class _Result(asyncio.CancelledError):
        """Chained from an Error if there was one."""

    async def _send_challenge_response(self, key: bytes, challenge: bytes):
        message = self._encrypt(key, challenge).hex()
        writer = self._writer
        writer.write(message.encode())
        await writer.drain()
        _logger.debug("\t<\t%s", message)

    def _compose_keys(self, old: bytes, new: bytes):
        return {
            self.SERVICE: self.SET_SYSTEM_PROPERTIES,
            self.PROPERTY_LIST: {
                self.KEYS: "".join(
                    [self._encrypt(old, key).hex() for key in (old, new)]
                )
            },
        }

    async def _consume_security_setkey(self):
        # } terminated json encoding
        frame = await asyncio.wait_for(self._reader.readuntil(b"}"), self._read_timeout)
        _logger.debug("\t>\t%s", frame.decode())
        try:
            message = json.loads(frame)
        except json.JSONDecodeError as error:
            _logger.error("except json.JSONDecodeError: %s %s", error, frame)
        else:
            self._address = message[self.MAC]

            async def handle(message: dict[str]):
                try:
                    self.StatusError(message).raise_if()
                except self.StatusError as error:
                    raise self._Result() from error
                else:
                    raise self._Result()

            await self.handle_send(
                handle, self._compose_keys(self.hash(b""), self._key)
            )

    async def _consume_security_hello(self):
        # space terminated challenge phrase
        challenge = (
            await asyncio.wait_for(self._reader.readuntil(b" "), self._read_timeout)
        )[:-1]
        _logger.debug("\t>\t\t%s", challenge.decode())
        # 12 byte MAC address
        self._address = await asyncio.wait_for(
            self._reader.readexactly(12), self._read_timeout
        )
        _logger.debug("\t>\t\t%s", self._address.decode())
        await self._send_challenge_response(
            self._key, bytes.fromhex(challenge.decode())
        )

    def _consume_security_hello_response(self, success: bool):
        if success:
            raise self._Result()
        raise self._Result() from self.Error("Invalid")

    def _consume_security_mac(self, message):
        self._address = message[self.MAC]
        raise self._Result()

    async def _unwrap_security_mac(self, frame):
        try:
            message = json.loads(frame)
            self._consume_security_mac(message)
        except json.JSONDecodeError as error:
            # this frame may be concatenated (improperly, for JSON) with another(s?).
            # rewrite/retry it as an array of frames
            frames = b"[" + frame.replace(b"}{", b"},{") + b"]"
            try:
                messages = json.loads(frames)
            except json.JSONDecodeError as error:
                _logger.error("except json.JSONDecodeError: %s %s", error, frames)
            else:
                mac, *others = messages
                try:
                    self._consume_security_mac(mac)
                finally:
                    for message in others:
                        await self.consume(message)

    async def unwrap(self, frame: bytes):
        if frame.startswith(self.SECURITY_MAC):
            await self._unwrap_security_mac(frame)
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

    async def session(self):
        try:
            await super().session()
        except self._Result as root:
            address = self._address
            self._address = None
            if root.__cause__ is None:
                return address
            raise root.__cause__ from None

    def __init__(
        self,
        key: bytes = KEY,
        read_timeout: float = Consumer.READ_TIMEOUT,
        reader: asyncio.StreamReader = None,
        writer: asyncio.StreamWriter = None,
    ):
        self._key = key
        super().__init__(read_timeout, reader, writer)
        self._address = None


class _ConnectionContext(contextlib.AbstractAsyncContextManager):
    def __init__(self, host: str, port: int):
        self._host = host
        self._port = port
        self._writer = None

    async def __aenter__(self):
        reader, self._writer = await asyncio.open_connection(self._host, self._port)
        return (reader, self._writer)

    async def __aexit__(self, et, ev, tb):
        self._writer.close()
        try:
            await self._writer.wait_closed()
        except OSError:
            pass


class Connector(Authenticator):
    """A Connector is an Authenticator that loops over connections/sessions."""

    # default arguments
    HOST: Final = "LCM1.local."
    PORT: Final = 2112
    LOOP_TIMEOUT: Final = 2 ** 8

    def cancel(self):
        """Cancel the task running loop()."""
        if self._task is not None:
            self._task.cancel()

    async def loop(self):
        """Return the result of the first successful connection/session.

        Raise OSError if (and why) connection could not be made, if loop_timeout < 0.
        Otherwise, sleep for up to loop_timeout seconds before trying again."""
        self._task = asyncio.current_task()
        count = 0
        try:
            while True:
                before = time.monotonic()
                try:
                    async with _ConnectionContext(self._host, self._port) as connection:
                        self._reader, self._writer = connection
                        # connection success, will be closed with context exit
                        try:
                            return await self.session()
                        except EOFError as error:
                            _logger.error("EOFError")
                        except OSError as error:
                            _logger.error("OSError %s", error)
                        except asyncio.TimeoutError:
                            _logger.error("asyncio.TimeoutError")
                        finally:
                            self._reader, self._writer = None, None
                except OSError as error:
                    # connection error
                    if self._loop_timeout < 0:
                        raise
                    _logger.error("OSError %s", error)
                duration = time.monotonic() - before
                if duration > self._loop_timeout:
                    count = 0
                else:
                    count += 1
                await asyncio.sleep(min(2 ** count, self._loop_timeout))
        finally:
            self._task = None

    def __init__(  # pylint: disable=too-many-arguments
        self,
        host: str = HOST,
        port: int = PORT,
        loop_timeout: float = LOOP_TIMEOUT,
        key: bytes = Authenticator.KEY,
        read_timeout: float = Consumer.READ_TIMEOUT,
    ):
        self._host = host
        self._port = port
        self._loop_timeout = loop_timeout
        super().__init__(key, read_timeout)
        self._task = None


class Hub(Connector):
    """A Hub is a Connector where each session acts as an Authenticator then Emitter."""

    async def session(self):
        await Authenticator.session(self)
        await Emitter.session(self)
