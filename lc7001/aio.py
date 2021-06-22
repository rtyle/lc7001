"""asyncio (aio) Legrand Adorne LC7001 Hub interface.

https://www.legrand.us/wiring-devices/electrical-accessories/miscellaneous/adorne-hub/p/lc7001
https://www.amazon.com/Legrand-Q-LC7001-Lighting-Controller/dp/B06XW1MLVF

https://www.legrand.us/solutions/smart-lighting/radio-frequency-lighting-controls
https://developer.legrand.com/documentation/rflc-api-for-lc7001/
"""

import abc
import asyncio
import collections
import json
import logging
from typing import Final, Type

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes

_logger: Final = logging.getLogger(__name__)


class _Session(abc.ABC):  # pylint: disable=too-few-public-methods
    # default factory arguments
    HOST: Final = "LCM1.local"
    PORT: Final = 2112
    TIMEOUT: Final = 60.0

    @classmethod
    async def factory(
        cls, host: str = HOST, port: int = PORT, timeout: float = TIMEOUT
    ):
        """Return an asyncio.run'able _SessionFactory for this class of _Session."""
        return await _SessionFactory(host, port, timeout, cls).main()

    @abc.abstractmethod
    async def main(self):
        """Run the session."""


class _SessionFactory:  # pylint: disable=too-few-public-methods
    """Construct a session for each connection, find current with session()."""

    def session(self):
        """Return the current session, perhaps None."""
        return self._session

    async def main(self):
        """Return an asyncio.run'able coroutine object."""

        while True:
            try:
                reader, writer = await asyncio.open_connection(self._host, self._port)
                self._session = self._type(writer, reader)
            except asyncio.TimeoutError:
                _logger.error("except asyncio.TimeoutError")
            except OSError as error:
                _logger.error("except OSError: %s", error)
                await asyncio.sleep(self._timeout)
            else:

                async def close(writer: asyncio.StreamWriter):
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except OSError:
                        # if session failed with ECONNRESET, so would this
                        pass

                try:
                    await self._session.main()
                    self._session = None
                except EOFError:
                    _logger.error("except EOFError")
                except OSError as error:
                    _logger.error("except OSError: %s", error)
                except asyncio.CancelledError:
                    _logger.error("except asyncio.CancelledError")
                    await close(writer)
                    raise
                except asyncio.TimeoutError:
                    _logger.error("except asyncio.TimeoutError")
                await close(writer)

    def __init__(self, host: str, port: int, timeout: float, _type: Type[_Session]):
        self._host = host
        self._port = port
        self._timeout = timeout
        self._type = _type
        self._session = None


class _Sender(_Session):  # pylint: disable=too-few-public-methods

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

    async def send_challenge_response(self, key: bytes, challenge: bytes):
        """Send a challenge response (the AES(key) encryption of challenge)."""
        message = self._encrypt(key, challenge).hex()
        self._writer.write(message.encode())
        await self._writer.drain()
        _logger.debug("\t< %s", message)

    async def send(self, message: dict[str]):
        """Send a composed message."""
        _id = self._id + 1
        message[self._ID] = _id
        self._id = _id
        self._writer.write(json.dumps(message).encode())
        self._writer.write(b"\x00")
        await self._writer.drain()
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

    def compose_list_scenes(self):
        """Compose a LIST_SCENES message."""
        return {self.SERVICE: self.LIST_SCENES}

    def compose_list_zones(self):
        """Compose a LIST_ZONES message."""
        return {self.SERVICE: self.LIST_ZONES}

    def compose_report_scene_properties(self, sid):
        """Compose a REPORT_SCENE_PROPERTIES message."""
        return {self.SERVICE: self.REPORT_SCENE_PROPERTIES, self.SID: sid}

    def compose_report_system_properties(self):
        """Compose a REPORT_SYSTEM_PROPERTIES message."""
        return {self.SERVICE: self.REPORT_SYSTEM_PROPERTIES}

    def compose_report_zone_properties(self, zid):
        """Compose a REPORT_ZONE_PROPERTIES message."""
        return {self.SERVICE: self.REPORT_ZONE_PROPERTIES, self.ZID: zid}

    def __init__(self, writer: asyncio.StreamWriter):
        self._writer = writer
        self._id = 0  # id of last send


class Consumer(_Sender):
    """A Consumer (is also a _Sender) whose messages are handled by an abstract consume method."""

    # default constructor values
    TIMEOUT: Final = 60.0

    # Security message prefixes
    SECURITY_HELLO: Final = "Hello V1 "
    SECURITY_INVALID: Final = "[INVALID]"
    SECURITY_OK: Final = "[OK]"
    SECURITY_SETKEY: Final = "[SETKEY]"

    # SECURITY_HELLO key, MAC message
    MAC: Final = "MAC"

    # ZONE PROPERTY_LIST keys
    DEVICE_TYPE: Final = "DeviceType"  # json_string, DIMMER/, consume only

    @abc.abstractmethod
    async def consume(self, message: dict[str]):
        """Consume a message."""

    @abc.abstractmethod
    async def consume_security_setkey(self, message: dict[str]):
        """Consume a SECURITY_SETKEY message."""

    @abc.abstractmethod
    async def consume_security_hello(self, challenge: bytes, address: bytes):
        """Consume a SECURITY_HELLO message."""

    @abc.abstractmethod
    async def consume_security_ok(self):
        """Consume a SECURITY_OK message from successful SECURITY_HELLO challenge response."""

    @abc.abstractmethod
    async def consume_security_invalid(self):
        """Consume a SECURITY_OK message from failed SECURITY_HELLO challenge response."""

    async def main(self):
        while True:
            # null terminated packet
            packet = (
                await asyncio.wait_for(self._reader.readuntil(b"\x00"), self._timeout)
            )[:-1]
            chars = packet.decode()
            if chars.startswith(self.SECURITY_SETKEY):
                # } terminated json encoding
                encoded = await asyncio.wait_for(
                    self._reader.readuntil(b"}"), self._timeout
                )
                try:
                    message = json.loads(encoded)
                except json.JSONDecodeError as error:
                    _logger.error(
                        "except json.JSONDecodeError: %s %s %s", error, chars, encoded
                    )
                else:
                    _logger.debug("\t> %s%s", self.SECURITY_SETKEY, message)
                    await self.consume_security_setkey(message)
            elif chars.startswith(self.SECURITY_HELLO):
                # space terminated challenge phrase
                challenge = (
                    await asyncio.wait_for(self._reader.readuntil(b" "), self._timeout)
                )[:-1]
                # 12 byte MAC address
                address = await asyncio.wait_for(
                    self._reader.readexactly(12), self._timeout
                )
                _logger.debug(
                    "\t> %s %s %s",
                    self.SECURITY_HELLO,
                    challenge.decode(),
                    address.decode(),
                )
                await self.consume_security_hello(challenge, address)
            elif chars.startswith(self.SECURITY_OK):
                _logger.debug("\t> %s", self.SECURITY_OK)
                await self.consume_security_ok()
            elif chars.startswith(self.SECURITY_INVALID):
                _logger.debug("\t> %s", self.SECURITY_INVALID)
                await self.consume_security_invalid()
            else:
                # workaround LC7001 JSON non-compliant bug
                # that sometimes causes messages to be concatenated.
                # change JSON encoding to be a list of messages.
                encoded = b"[" + packet.replace(b"}{", b"},{") + b"]"
                try:
                    decoded = json.loads(encoded)
                except json.JSONDecodeError as error:
                    _logger.error("except json.JSONDecodeError: %s %s", error, encoded)
                else:
                    for message in decoded:
                        _logger.debug("\t> %s", message)
                        await self.consume(message)

    def __init__(
        self,
        writer: asyncio.StreamWriter,
        reader: asyncio.StreamReader,
        timeout: float = TIMEOUT,
    ):
        super().__init__(writer)
        self._reader = reader
        self._timeout = timeout


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

    # events emitted with security messages
    EVENT_SECURITY_HELLO: Final = Consumer.SECURITY_HELLO
    EVENT_SECURITY_INVALID: Final = Consumer.SECURITY_INVALID
    EVENT_SECURITY_OK: Final = Consumer.SECURITY_OK
    EVENT_SECURITY_SETKEY: Final = Consumer.SECURITY_SETKEY

    # events emitted with message
    EVENT_MAC: Final = Consumer.MAC
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
        elif self.MAC in message:
            await self._emit(self.EVENT_MAC, message)

    async def consume_security_setkey(self, message: dict[str]):
        await self._emit(self.EVENT_SECURITY_SETKEY, message)

    async def consume_security_hello(self, challenge: bytes, address: bytes):
        await self._emit(self.EVENT_SECURITY_HELLO, challenge, address)

    async def consume_security_ok(self):
        await self._emit(self.EVENT_SECURITY_OK)

    async def consume_security_invalid(self):
        await self._emit(self.EVENT_SECURITY_INVALID)

    async def handle_send(self, handler: collections.abc.Awaitable, message: dict[str]):
        """Handle the response from send(message)."""
        self.once(f"{self._ID}:{self._id + 1}", handler)
        await self.send(message)

    def __init__(
        self,
        writer: asyncio.StreamWriter,
        reader: asyncio.StreamReader,
        timeout: float = Consumer.TIMEOUT,
    ):
        Consumer.__init__(self, writer, reader, timeout)
        _EventEmitter.__init__(self)
        self._emit_id = 1  # id of next emit
