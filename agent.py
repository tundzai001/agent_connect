"""Single-file Linux agent for MQTT control, WSS fallback and WebRTC shell."""

import asyncio
import base64
import contextvars
import errno
import hashlib
import hmac
import json
import logging
import os
import platform
import re
import signal
import socket
import shutil
import threading
import time
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote
from urllib.request import Request, urlopen
from urllib.error import HTTPError

if os.name == "posix":
    import fcntl
    import pty
    import struct
    import termios

try:
    import paho.mqtt.client as mqtt
except ImportError:  # pragma: no cover - production requirements install it
    mqtt = None

try:
    import websockets
except ImportError:  # pragma: no cover - production requirements install it
    websockets = None

try:  # Keep heartbeat/inventory usable if aiortc wheels are unavailable.
    from aiortc import RTCConfiguration, RTCIceServer, RTCPeerConnection, RTCSessionDescription
except ImportError:  # pragma: no cover - exercised on minimal agent installs
    RTCConfiguration = RTCIceServer = RTCPeerConnection = RTCSessionDescription = None


for _name, _value in {
    "AITOGY_CONTROL_URL": "https://connect.aitogy.com",
    "AITOGY_MQTT_HOST": "aitogy.asia",
    "AITOGY_MQTT_PORT": "1883",
    "AITOGY_MQTT_TLS": "false",
    "AITOGY_MQTT_USERNAME": "mqttUser",
    "AITOGY_MQTT_TOPIC_PREFIX": "aitogy/devices",
    "AITOGY_STUN_URLS": "stun:aitogy.asia:3478",
    "AITOGY_TURN_URLS": "turn:aitogy.asia:3478?transport=udp,turns:aitogy.asia:5349?transport=tcp",
    "AITOGY_TURN_TTL_SECONDS": "3600",
}.items():
    os.environ.setdefault(_name, _value)
logging.basicConfig(level=os.getenv("AITOGY_LOG_LEVEL", "INFO"))
logger = logging.getLogger("agent")

AGENT_VERSION = "1.2.8"
HEARTBEAT_INTERVAL_SECONDS = max(
    5, min(int(os.getenv("AITOGY_HEARTBEAT_INTERVAL_SECONDS", "30")), 300)
)

_ARM_CPU_MODELS = {
    ("0x41", "0xb76"): "ARM1176JZF-S",
    ("0x41", "0xc07"): "Cortex-A7",
    ("0x41", "0xd03"): "Cortex-A53",
    ("0x41", "0xd08"): "Cortex-A72",
    ("0x41", "0xd0b"): "Cortex-A76",
}
_ARM_IMPLEMENTERS = {"0x41", "0x00000041"}
_RPI_SOC_CPU_MODELS = {"bcm2711": "Cortex-A72", "bcm2712": "Cortex-A76"}


def _env_bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).lower() in {"1", "true", "yes", "on"}


def _canonical_command(command: dict) -> bytes:
    fields = {
        key: command.get(key)
        for key in ("command_id", "device_id", "command_type", "payload", "issued_at", "expires_at")
    }
    return json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _verify_command(command: dict, key: str) -> bool:
    signature = str(command.get("signature") or "")
    if not key or not signature:
        return False
    expected = hmac.new(key.encode("utf-8"), _canonical_command(command), hashlib.sha256).hexdigest()
    return hmac.compare_digest(signature, expected)


def _default_device_id() -> str:
    for machine_id_path in (Path("/etc/machine-id"), Path("/var/lib/dbus/machine-id")):
        try:
            machine_id = machine_id_path.read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if machine_id:
            return f"aitogy-{machine_id[:24]}"
    hostname = "".join(
        character if character.isalnum() or character in "-_" else "-"
        for character in socket.gethostname()
    )
    return f"aitogy-{hostname.lower() or 'linux-agent'}"


def _state_dir() -> Path:
    default = Path("/agent_connect") if os.name != "nt" else Path(".agent-connect")
    return Path(os.getenv("AITOGY_STATE_DIR", str(default)))


def _read_text(path: str, maximum: int = 8192) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")[:maximum].strip()
    except OSError:
        return ""


def _write_secret(path: Path, value: str) -> None:
    """Persist one credential outside the human-readable agent state."""
    if not value:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(value, encoding="utf-8")
    if os.name == "posix":
        temporary.chmod(0o600)
    os.replace(temporary, path)
    if os.name == "posix":
        path.chmod(0o600)


def _cpuinfo_value(*names: str) -> str:
    wanted = {name.lower() for name in names}
    for line in _read_text("/proc/cpuinfo", 32768).splitlines():
        key, separator, value = line.partition(":")
        if separator and key.strip().lower() in wanted and value.strip():
            return value.strip()
    return ""


def _cpu_model() -> str:
    model_name = ""
    hardware = ""
    processor_fallback = ""
    cpu_implementer = ""
    cpu_part = ""
    for line in _read_text("/proc/cpuinfo", 32768).splitlines():
        key, separator, value = line.partition(":")
        if not separator:
            continue
        key_lower = key.strip().lower()
        candidate = value.strip()
        if key_lower == "model name" and not model_name:
            model_name = candidate
        elif key_lower == "hardware" and not hardware:
            hardware = candidate
        elif key_lower == "cpu implementer" and not cpu_implementer:
            cpu_implementer = candidate.lower()
        elif key_lower == "cpu part" and not cpu_part:
            cpu_part = candidate.lower()
        elif (
            key_lower == "processor"
            and not processor_fallback
            and candidate
            and not candidate.isdecimal()
        ):
            processor_fallback = candidate

    arm_part_model = (
        _ARM_CPU_MODELS.get((cpu_implementer, cpu_part))
        if cpu_implementer in _ARM_IMPLEMENTERS
        else None
    )
    rpi_soc_model = _RPI_SOC_CPU_MODELS.get(hardware.lower())
    generic_arm_label = re.compile(r"^armv\d+ processor rev", re.IGNORECASE)
    return next(
        (
            candidate
            for candidate in (model_name, arm_part_model, rpi_soc_model, processor_fallback)
            if candidate and not candidate.isdecimal() and not generic_arm_label.match(candidate)
        ),
        "",
    )


def _os_release() -> dict[str, str]:
    result: dict[str, str] = {}
    for line in _read_text("/etc/os-release", 8192).splitlines():
        key, separator, value = line.partition("=")
        if separator and key and value:
            result[key.strip()] = value.strip().strip('"').strip("'")
    return result


def _hardware_inventory(device_id: str) -> dict[str, object]:
    memory_total = None
    for line in _read_text("/proc/meminfo", 8192).splitlines():
        key, separator, value = line.partition(":")
        if key.strip() == "MemTotal" and separator:
            try:
                memory_total = int(value.strip().split()[0]) * 1024
            except (IndexError, ValueError):
                pass
            break
    os_release = _os_release()
    serial = _cpuinfo_value("Serial")
    model = ""
    for model_path in ("/proc/device-tree/model", "/sys/firmware/devicetree/base/model"):
        try:
            model = (
                Path(model_path)
                .read_bytes()[:1024]
                .replace(b"\x00", b"")
                .decode("utf-8", errors="replace")
                .strip()
            )
        except OSError:
            continue
        if model:
            break
    try:
        disk_total = shutil.disk_usage("/").total
    except OSError:
        disk_total = None
    return {
        "device_uuid": device_id,
        "schema_version": "1",
        "model": model or None,
        "serial_number": serial or None,
        "architecture": platform.machine() or None,
        "cpu_model": _cpu_model() or None,
        "cpu_cores": os.cpu_count(),
        "ram_total_bytes": memory_total,
        "root_fs_total_bytes": disk_total,
        "os_pretty_name": os_release.get("PRETTY_NAME") or os_release.get("NAME"),
        "os_id": os_release.get("ID"),
        "os_id_like": os_release.get("ID_LIKE"),
        "os_version": os_release.get("VERSION_ID") or os_release.get("VERSION"),
        "kernel_version": platform.release() or None,
        "extra_json": {},
        "collected_at": datetime.now(timezone.utc).isoformat(),
    }


def _cpu_times() -> tuple[int, int] | None:
    """Return Linux aggregate CPU ticks as (total, idle)."""
    first_line = _read_text("/proc/stat", 4096).splitlines()
    if not first_line or not first_line[0].startswith("cpu "):
        return None
    try:
        values = [int(value) for value in first_line[0].split()[1:]]
    except ValueError:
        return None
    if len(values) < 4:
        return None
    return sum(values), values[3] + (values[4] if len(values) > 4 else 0)


def _memory_health() -> dict[str, float | int | None]:
    values: dict[str, int] = {}
    for line in _read_text("/proc/meminfo", 16384).splitlines():
        key, separator, raw_value = line.partition(":")
        if not separator:
            continue
        try:
            values[key] = int(raw_value.strip().split()[0]) * 1024
        except (IndexError, ValueError):
            continue
    total = values.get("MemTotal", 0)
    available = values.get("MemAvailable")
    if available is None:
        available = sum(values.get(key, 0) for key in ("MemFree", "Buffers", "Cached"))
    used = max(0, total - available) if total else 0
    return {
        "total_mb": round(total / (1024**2)) if total else None,
        "used_mb": round(used / (1024**2)) if total else None,
        "percent": round((used / total) * 100, 1) if total else None,
    }


def _cpu_temperature() -> float | None:
    thermal_root = Path("/sys/class/thermal")
    candidates: list[tuple[int, Path]] = []
    try:
        zones = list(thermal_root.glob("thermal_zone*"))
    except OSError:
        zones = []
    for zone in zones:
        zone_type = _read_text(str(zone / "type"), 128).lower()
        priority = 0 if any(name in zone_type for name in ("cpu", "soc", "x86_pkg")) else 1
        candidates.append((priority, zone / "temp"))
    for _, path in sorted(candidates, key=lambda item: item[0]):
        try:
            value = float(path.read_text(encoding="utf-8").strip())
        except (OSError, ValueError):
            continue
        celsius = value / 1000.0 if abs(value) >= 1000 else value
        if -20 <= celsius <= 150:
            return round(celsius, 1)
    return None


def _uptime_seconds() -> int | None:
    try:
        return max(0, int(float(_read_text("/proc/uptime", 256).split()[0])))
    except (IndexError, ValueError):
        return None


class AtomicCommitUncertain(OSError):
    """The new generation is visible, but its directory fsync failed."""


def _atomic_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    published = False
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            if os.name == "posix":
                os.fchmod(stream.fileno(), 0o600)
            json.dump(payload, stream, separators=(",", ":"))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        published = True
        if os.name == "posix":
            directory = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    except OSError as error:
        if published:
            raise AtomicCommitUncertain("Published state requires durability confirmation") from error
        raise
    finally:
        temporary.unlink(missing_ok=True)


class CommandJournal:
    """Bounded durable command intents and results; reads legacy ID-only lists."""

    def __init__(self, path: Path, limit: int = 512) -> None:
        self.path = path
        self.limit = limit
        self.entries: dict[str, dict | None] = {}
        self.intents: dict[str, dict] = {}
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return
        except (OSError, ValueError) as error:
            raise RuntimeError("Command journal cannot be read safely") from error
        if isinstance(loaded, list):
            self.entries = {str(item): None for item in loaded[-limit:] if item}
        elif isinstance(loaded, dict) and loaded.get("version") == 2 and isinstance(loaded.get("entries"), dict):
            self.entries = dict(list(loaded["entries"].items())[-limit:])
            if any(value is not None and not isinstance(value, dict) for value in self.entries.values()):
                raise RuntimeError("Invalid command journal result")
            intents = loaded.get("intents", {})
            if not isinstance(intents, dict) or any(not isinstance(value, dict) for value in intents.values()):
                raise RuntimeError("Invalid command journal intent")
            self.intents = {key: value for key, value in intents.items() if key in self.entries}
        else:
            raise RuntimeError("Unknown command journal format")

    def seen(self, command_id: str) -> bool:
        return command_id in self.entries

    def result(self, command_id: str) -> dict | None:
        return self.entries.get(command_id)

    def _store(self, command_id: str, result: dict | None, intent: dict | None = None) -> None:
        entries = {**self.entries, command_id: result}
        entries = dict(list(entries.items())[-self.limit:])
        intents = {key: value for key, value in self.intents.items() if key in entries}
        if intent is not None:
            intents[command_id] = intent
        if result is not None:
            intents.pop(command_id, None)
        _atomic_json(self.path, {"version": 2, "entries": entries, "intents": intents})
        self.entries = entries
        self.intents = intents

    def add(self, command_id: str, intent: dict | None = None) -> None:
        if not self.seen(command_id):
            self._store(command_id, None, intent)

    def complete(self, command_id: str, result: dict) -> None:
        if self.result(command_id) != result:
            self._store(command_id, result)


MessageHandler = Callable[[dict], Awaitable[None]]


class PtyShell:
    """A real Linux terminal, including job control and window resizing."""

    def __init__(self, pid: int, master_fd: int) -> None:
        self.pid = pid
        self.master_fd = master_fd
        self.closed = False

    @classmethod
    async def start(cls, columns: int = 120, rows: int = 32) -> "PtyShell":
        if os.name != "posix":
            raise RuntimeError("Interactive PTY shells require Linux")
        master_fd, slave_fd = pty.openpty()
        pid = os.fork()
        if pid == 0:
            os.close(master_fd)
            os.setsid()
            fcntl.ioctl(slave_fd, termios.TIOCSCTTY, 0)
            for descriptor in (0, 1, 2):
                os.dup2(slave_fd, descriptor)
            if slave_fd > 2:
                os.close(slave_fd)
            environment = {**os.environ, "TERM": "xterm-256color", "COLORTERM": "truecolor"}
            try:
                os.execvpe("/bin/bash", ["/bin/bash", "-l", "-i"], environment)
            finally:
                os._exit(127)
        os.close(slave_fd)
        shell = cls(pid, master_fd)
        shell.resize(columns, rows)
        return shell

    async def read(self) -> bytes:
        try:
            return await asyncio.to_thread(os.read, self.master_fd, 4096)
        except OSError as error:
            if self.closed or error.errno in {errno.EBADF, errno.EIO}:
                return b""
            raise

    def write(self, data: str | bytes) -> None:
        if self.closed:
            return
        raw = data.encode() if isinstance(data, str) else data
        os.write(self.master_fd, raw[:65536])

    def resize(self, columns: int, rows: int) -> None:
        if self.closed:
            return
        columns = max(20, min(int(columns), 500))
        rows = max(5, min(int(rows), 200))
        fcntl.ioctl(self.master_fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, columns, 0, 0))

    async def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        try:
            os.killpg(self.pid, signal.SIGHUP)
        except ProcessLookupError:
            pass
        try:
            os.close(self.master_fd)
        except OSError:
            pass
        try:
            await asyncio.to_thread(os.waitpid, self.pid, 0)
        except ChildProcessError:
            pass


class AitogyWebSocketControl:
    """Persistent WSS control/signaling fallback for a Linux agent."""

    def __init__(self, url: str, on_message: MessageHandler, on_connected=None) -> None:
        self.url = url
        self.on_message = on_message
        self.on_connected = on_connected
        self._outbox: asyncio.Queue[dict] = asyncio.Queue(maxsize=256)
        self._stop = asyncio.Event()
        self.connected = False
        self._socket = None

    async def send(self, message: dict) -> None:
        await self._outbox.put(message)

    async def close(self) -> None:
        self._stop.set()
        if self._socket is not None:
            await self._socket.close()

    async def run(self) -> None:
        if websockets is None:
            raise RuntimeError("websockets is required for the WSS fallback")
        delay = 1
        while not self._stop.is_set():
            try:
                async with websockets.connect(
                    self.url,
                    additional_headers={"User-Agent": "agent"},
                    ping_interval=20,
                    ping_timeout=20,
                    close_timeout=5,
                    max_size=2 * 1024 * 1024,
                ) as socket_connection:
                    self.connected = True
                    self._socket = socket_connection
                    delay = 1
                    sender = asyncio.create_task(self._send_loop(socket_connection))
                    receiver = asyncio.create_task(self._receive_loop(socket_connection))
                    replay = asyncio.create_task(self._announce_connected())
                    try:
                        done, _ = await asyncio.wait(
                            {sender, receiver}, return_when=asyncio.FIRST_COMPLETED
                        )
                        for task in done:
                            task.result()
                    finally:
                        sender.cancel()
                        receiver.cancel()
                        replay.cancel()
                        await asyncio.gather(sender, receiver, replay, return_exceptions=True)
            except asyncio.CancelledError:
                raise
            except Exception as error:  # pragma: no cover - network dependent
                logger.warning("Agent WSS unavailable: %s", error)
            finally:
                self.connected = False
                self._socket = None
            if not self._stop.is_set():
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=delay)
                except asyncio.TimeoutError:
                    pass
                delay = min(delay * 2, 30)

    async def _announce_connected(self) -> None:
        if self.on_connected is not None:
            try:
                await self.on_connected()
            except Exception:
                logger.exception("Could not replay results after WSS reconnect")

    async def _send_loop(self, socket_connection) -> None:
        while True:
            await socket_connection.send(
                json.dumps(await self._outbox.get(), separators=(",", ":"))
            )

    async def _receive_loop(self, socket_connection) -> None:
        async for raw in socket_connection:
            await self.on_message(json.loads(raw))


SignalSender = Callable[[dict], Awaitable[None]]


class WebRtcPeerManager:
    """WebRTC data-channel endpoint for a Linux shell session."""

    def __init__(
        self,
        send_signal: SignalSender,
        stun_urls: list[str],
        turn_urls: list[str],
        turn_username: str,
        turn_credential: str,
        turn_shared_secret: str = "",
        turn_ttl_seconds: int = 3600,
    ):
        self.send_signal = send_signal
        self.stun_urls = stun_urls
        self.turn_urls = turn_urls
        self.turn_username = turn_username
        self.turn_credential = turn_credential
        self.turn_shared_secret = turn_shared_secret
        self.turn_ttl_seconds = turn_ttl_seconds
        self._peers = set()
        self._shells: set[PtyShell] = set()

    async def handle_signal(self, payload: dict) -> None:
        if payload.get("type") != "offer":
            return
        if RTCPeerConnection is None:
            await self.send_signal(
                {"type": "error", "detail": "aiortc is not installed on this agent"}
            )
            return
        ice_servers = []
        if self.stun_urls:
            ice_servers.append(RTCIceServer(urls=self.stun_urls))
        if self.turn_urls:
            turn_username, turn_credential = self._turn_credentials()
            ice_servers.append(
                RTCIceServer(
                    urls=self.turn_urls,
                    username=turn_username,
                    credential=turn_credential,
                )
            )
        peer = RTCPeerConnection(RTCConfiguration(iceServers=ice_servers))
        self._peers.add(peer)

        @peer.on("datachannel")
        def on_datachannel(channel) -> None:
            if channel.label == "shell":
                asyncio.create_task(self._attach_shell(peer, channel))

        @peer.on("connectionstatechange")
        async def on_connectionstatechange() -> None:
            if peer.connectionState in {"failed", "closed", "disconnected"}:
                await self._close_peer(peer)

        await peer.setRemoteDescription(
            RTCSessionDescription(sdp=payload["sdp"], type="offer")
        )
        answer = await peer.createAnswer()
        await peer.setLocalDescription(answer)
        await self._wait_for_ice(peer)
        await self.send_signal(
            {
                "type": "answer",
                "session_id": payload.get("session_id"),
                "sdp": peer.localDescription.sdp,
            }
        )

    async def _attach_shell(self, peer, channel) -> None:
        shell = await PtyShell.start()
        self._shells.add(shell)

        @channel.on("message")
        def on_message(data) -> None:
            if isinstance(data, str) and data.startswith("{"):
                try:
                    message = json.loads(data)
                except json.JSONDecodeError:
                    message = None
                if message and message.get("type") == "resize":
                    shell.resize(message.get("cols", 120), message.get("rows", 32))
                    return
                if message and message.get("type") == "input":
                    shell.write(str(message.get("data", "")))
                    return
            shell.write(data)

        try:
            while channel.readyState == "open":
                chunk = await shell.read()
                if not chunk:
                    break
                channel.send(chunk.decode("utf-8", errors="replace"))
        finally:
            await shell.close()
            self._shells.discard(shell)
            await self._close_peer(peer)

    async def _wait_for_ice(self, peer) -> None:
        for _ in range(100):
            if peer.iceGatheringState == "complete":
                return
            await asyncio.sleep(0.05)

    async def _close_peer(self, peer) -> None:
        if peer in self._peers:
            self._peers.discard(peer)
            await peer.close()

    async def close(self) -> None:
        for peer in list(self._peers):
            await self._close_peer(peer)
        for shell in list(self._shells):
            await shell.close()

    def _turn_credentials(self) -> tuple[str, str]:
        if not self.turn_shared_secret:
            return self.turn_username, self.turn_credential
        username = f"{int(time.time()) + self.turn_ttl_seconds}:agent"
        credential = base64.b64encode(
            hmac.new(
                self.turn_shared_secret.encode(), username.encode(), hashlib.sha1
            ).digest()
        ).decode()
        return username, credential


class Agent:
    def __init__(self) -> None:
        if mqtt is None or websockets is None:
            raise RuntimeError("Install requirements.txt before starting the agent")
        self.state_dir = _state_dir()
        self.state_path = self.state_dir / "agent.json"
        self.token_path = self.state_dir / "device.token"
        self.command_key_path = self.state_dir / "command.key"
        self.credentials_path = self.state_dir / "credentials.json"
        self._state = self._load_state()
        if self.credentials_path.exists():
            try:
                credentials = json.loads(self.credentials_path.read_text(encoding="utf-8"))
                required = ("device_id", "name", "device_token", "command_signing_key")
                if not isinstance(credentials, dict) or any(not isinstance(credentials.get(key), str) for key in required):
                    raise ValueError("invalid credential bundle")
                if bool(credentials["device_token"]) != bool(credentials["command_signing_key"]):
                    raise ValueError("incomplete credential bundle")
                if not credentials["device_id"] or not isinstance(credentials.get("provisioned"), bool):
                    raise ValueError("invalid credential identity or state")
                if credentials["provisioned"] != bool(credentials["device_token"]):
                    raise ValueError("credential state does not match keys")
                configured_id = os.getenv("AITOGY_DEVICE_ID")
                if configured_id and configured_id != credentials["device_id"]:
                    raise ValueError("configured device identity differs from credentials")
            except (OSError, ValueError, TypeError) as error:
                raise RuntimeError("Credential bundle cannot be read safely; refusing legacy fallback") from error
            self.device_id = credentials["device_id"]
            self.device_name = credentials["name"]
            self.device_token = credentials["device_token"]
            self.command_signing_key = credentials["command_signing_key"]
            self.provisioned = bool(self.device_token and self.command_signing_key)
        else:
            self.device_id = os.getenv("AITOGY_DEVICE_ID") or self._state.get("device_id") or _default_device_id()
            self.device_name = str(self._state.get("name") or "").strip()
            self.device_token = _read_text(str(self.token_path), 4096) or str(self._state.get("device_token") or "").strip()
            self.command_signing_key = _read_text(str(self.command_key_path), 4096) or str(self._state.get("command_signing_key") or "").strip()
            self.provisioned = bool(self.device_token and self.command_signing_key)
            if self.provisioned:
                self._save_state()
        self.topic_prefix = os.getenv("AITOGY_MQTT_TOPIC_PREFIX", "aitogy/devices")
        self.mqtt_connected = False
        self._loop: asyncio.AbstractEventLoop | None = None
        self._stop = asyncio.Event()
        self._command_lock = asyncio.Lock()
        self._signal_transport = contextvars.ContextVar("signal_transport", default=None)
        default_journal = self.state_dir / "commands.json"
        self._journal = CommandJournal(
            Path(os.getenv("AITOGY_COMMAND_JOURNAL", default_journal))
        )
        self._ws: AitogyWebSocketControl | None = None
        self._ws_task: asyncio.Task | None = None
        self._shells: dict[str, PtyShell] = {}
        self._shell_readers: dict[str, asyncio.Task] = {}
        self._health_lock = threading.Lock()
        self._health_cache: dict[str, object] = {}
        self._health_cached_at = 0.0
        self._previous_cpu_times: tuple[int, int] | None = None
        self._webrtc = WebRtcPeerManager(
            self._send_signal,
            [
                item.strip()
                for item in os.getenv("AITOGY_STUN_URLS", "").split(",")
                if item.strip()
            ],
            [
                item.strip()
                for item in os.getenv("AITOGY_TURN_URLS", "").split(",")
                if item.strip()
            ],
            os.getenv("AITOGY_TURN_USERNAME", ""),
            os.getenv("AITOGY_TURN_CREDENTIAL", ""),
            os.getenv("AITOGY_TURN_SHARED_SECRET", ""),
            int(os.getenv("AITOGY_TURN_TTL_SECONDS", "3600")),
        )
        self._mqtt = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=f"agent-{self.device_id}")
        self._mqtt.max_queued_messages_set(256)
        self._mqtt.enable_logger(logger)
        self._mqtt.reconnect_delay_set(min_delay=1, max_delay=30)
        self._mqtt.on_connect = self._on_mqtt_connect
        self._mqtt.on_disconnect = self._on_mqtt_disconnect
        self._mqtt.on_message = self._on_mqtt_message
        username = os.getenv("AITOGY_MQTT_USERNAME")
        if username:
            self._mqtt.username_pw_set(username, os.getenv("AITOGY_MQTT_PASSWORD"))
        if _env_bool("AITOGY_MQTT_TLS", False):
            self._mqtt.tls_set(ca_certs=os.getenv("AITOGY_MQTT_CA_FILE") or None)

    def _load_state(self) -> dict:
        try:
            loaded = json.loads(self.state_path.read_text(encoding="utf-8"))
            return loaded if isinstance(loaded, dict) else {}
        except (FileNotFoundError, OSError, ValueError, TypeError):
            return {}

    def _save_state(self) -> None:
        payload = {
            "device_id": self.device_id, "name": self.device_name,
            "provisioned": bool(self.provisioned and self.device_token and self.command_signing_key),
        }
        # One authoritative commit includes identity, name, and both credentials.
        _atomic_json(self.credentials_path, {
            **payload, "device_token": self.device_token,
            "command_signing_key": self.command_signing_key,
        })
        try:
            # Compatibility mirrors are not read when credentials.json exists.
            _write_secret(self.token_path, self.device_token)
            _write_secret(self.command_key_path, self.command_signing_key)
            _atomic_json(self.state_path, payload)
        except OSError:
            logger.warning("Credential bundle committed; compatibility mirrors could not be updated")

    def _pairing_token(self) -> str:
        configured = os.getenv("AITOGY_PAIRING_TOKEN", "").strip()
        if configured:
            return configured
        return _read_text(str(self.state_dir / "pairing.token"), 512)

    def _pair_with_control_plane(self) -> bool:
        pairing_token = self._pairing_token()
        if not pairing_token:
            return False
        control_url = os.getenv("AITOGY_CONTROL_URL", "https://connect.aitogy.com").rstrip("/")
        body = json.dumps(
            {
                "pairing_token": pairing_token,
                "device_id": self.device_id,
                "name": os.getenv("AITOGY_DEVICE_NAME", "").strip() or socket.gethostname(),
            }
        ).encode("utf-8")
        request = Request(
            f"{control_url}/api/devices/register",
            data=body,
            headers={"Content-Type": "application/json", "User-Agent": "aitogy-agent"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=20) as response:
                result = json.loads(response.read().decode("utf-8"))
        except HTTPError as error:
            self._pairing_rejected = error.code in {400, 401, 403, 404, 410}
            if error.code == 409:
                try:
                    detail = json.loads(error.read(2048)).get("detail")
                except (OSError, ValueError, AttributeError):
                    detail = None
                self._pairing_rejected = detail != "another activation is already in progress"
            error.close()
            logger.warning("Pairing rejected (HTTP %s); %s", error.code,
                "create a new pairing token" if self._pairing_rejected else "request will be retried")
            return False
        except Exception as error:  # pragma: no cover - network dependent
            logger.warning("Pairing request failed: %s", error)
            return False
        if not isinstance(result, dict):
            logger.warning("Invalid pairing response")
            return False
        device_token = str(result.get("device_token") or "").strip()
        command_signing_key = str(result.get("command_signing_key") or "").strip()
        if len(device_token) < 32 or not command_signing_key:
            logger.warning("Pairing response did not include device credentials")
            return False
        previous_state = (self.device_name, self.device_token, self.command_signing_key, self.provisioned)
        self.device_token = device_token
        self.command_signing_key = command_signing_key
        self.device_name = str(result.get("name") or os.getenv("AITOGY_DEVICE_NAME", "").strip() or socket.gethostname())[:160]
        self.provisioned = True
        try:
            self._save_state()
        except OSError:
            self.device_name, self.device_token, self.command_signing_key, self.provisioned = previous_state
            logger.exception("Pairing credentials could not be committed; request will be retried")
            return False
        pairing_file = self.state_dir / "pairing.token"
        try:
            pairing_file.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            logger.warning("Could not remove consumed pairing token file")
        logger.info("Agent paired as %s", self.device_name)
        return True

    async def _pairing_loop(self) -> None:
        while not self._stop.is_set() and not self.provisioned:
            if self._pairing_token():
                async with self._command_lock:
                    if not self.provisioned and await asyncio.to_thread(self._pair_with_control_plane):
                        self._start_websocket()
                        return
                    if getattr(self, "_pairing_rejected", False):
                        return
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=30)
            except asyncio.TimeoutError:
                pass

    def _start_websocket(self) -> None:
        # An old token can remain on disk after the server has reset/revoked a
        # device. Do not hammer the endpoint with guaranteed 403s until the
        # device is provisioned again; provisioning calls this method again.
        if not self._loop or self._ws_task or not self.provisioned or not self.device_token:
            return
        self._ws = AitogyWebSocketControl(self._ws_url(), self._handle_ws_message,
            lambda: self._replay_results("websocket"))
        self._ws_task = asyncio.create_task(self._ws.run())

    async def _restart_websocket(self) -> None:
        previous = self._ws
        previous_task = self._ws_task
        self._ws = None
        self._ws_task = None
        if previous is not None:
            await previous.close()
        if previous_task is not None:
            previous_task.cancel()
            await asyncio.gather(previous_task, return_exceptions=True)
        self._start_websocket()

    def _ws_url(self) -> str:
        if not self.device_token:
            return ""
        configured = os.getenv("AITOGY_AGENT_WS_URL", "").rstrip("/")
        if configured:
            base = configured
        else:
            base = os.getenv("AITOGY_CONTROL_URL", "https://connect.aitogy.com").rstrip("/")
            base = base.replace("https://", "wss://").replace("http://", "ws://")
            base += "/ws/agent"
        return f"{base}/{quote(self.device_id, safe='')}?token={quote(self.device_token, safe='')}"

    async def run(self) -> None:
        self._loop = asyncio.get_running_loop()
        for signum in (signal.SIGINT, signal.SIGTERM):
            try:
                self._loop.add_signal_handler(signum, self._stop.set)
            except (NotImplementedError, RuntimeError):
                pass
        self._mqtt.connect_async(
            os.getenv("AITOGY_MQTT_HOST", "aitogy.asia"),
            int(os.getenv("AITOGY_MQTT_PORT", "1883")),
            60,
        )
        self._mqtt.loop_start()
        self._start_websocket()
        pairing_task = asyncio.create_task(self._pairing_loop()) if not self.provisioned else None
        heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        try:
            await self._stop.wait()
        finally:
            tasks = [task for task in (self._ws_task, heartbeat_task, pairing_task) if task is not None]
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await self._webrtc.close()
            for session_id in list(self._shells):
                await self._close_shell(session_id)
            if self._ws:
                await self._ws.close()
            self._mqtt.loop_stop()
            self._mqtt.disconnect()

    async def _heartbeat_loop(self) -> None:
        while True:
            message = {"type": "heartbeat", "payload": self._inventory()}
            if self.mqtt_connected:
                self._publish_event(message)
            if self._ws and self._ws.connected:
                await self._ws.send(message)
            await asyncio.sleep(HEARTBEAT_INTERVAL_SECONDS)

    def _system_health(self) -> dict[str, object]:
        """Collect one coherent live sample for both control transports."""
        now = time.monotonic()
        with self._health_lock:
            if self._health_cache and now - self._health_cached_at < 5:
                return dict(self._health_cache)

            cpu_percent: float | None = None
            current_cpu_times = _cpu_times()
            if current_cpu_times and self._previous_cpu_times:
                total_delta = current_cpu_times[0] - self._previous_cpu_times[0]
                idle_delta = current_cpu_times[1] - self._previous_cpu_times[1]
                if total_delta > 0:
                    cpu_percent = round(
                        max(0.0, min(100.0, (1 - idle_delta / total_delta) * 100)),
                        1,
                    )
            if current_cpu_times:
                self._previous_cpu_times = current_cpu_times
            if cpu_percent is None:
                try:
                    cpu_percent = round(
                        max(0.0, min(100.0, os.getloadavg()[0] / max(1, os.cpu_count() or 1) * 100)),
                        1,
                    )
                except (AttributeError, OSError):
                    pass

            sample: dict[str, object] = {
                "cpu": {"usage_percent": cpu_percent, "count": os.cpu_count()},
                "memory": _memory_health(),
                "temperature": {"celsius": _cpu_temperature()},
                "uptime_seconds": _uptime_seconds(),
                "timestamp": int(time.time()),
            }
            self._health_cache = sample
            self._health_cached_at = now
            return dict(sample)

    def _inventory(self) -> dict:
        token_fingerprint = (
            hashlib.sha256(self.device_token.encode()).hexdigest()[:16]
            if self.device_token
            else None
        )
        return {
            **_hardware_inventory(self.device_id),
            "device_id": self.device_id,
            "name": self.device_name,
            "hostname": socket.gethostname(),
            "platform": platform.system().lower(),
            "architecture": platform.machine(),
            "agent_version": AGENT_VERSION,
            "capabilities": {"webrtc": True, "shell": True, "screen": False},
            "status": "online" if self.provisioned else "unprovisioned",
            "provisioned": self.provisioned,
            "token_fingerprint": token_fingerprint,
            "system_info": self._system_health(),
            "heartbeat_interval_seconds": HEARTBEAT_INTERVAL_SECONDS,
            "sent_at": int(time.time()),
        }

    async def _handle_ws_message(self, message: dict) -> None:
        if message.get("type") == "signal":
            await self._handle_signal(message.get("payload") or {}, "websocket")
        elif message.get("type") == "command":
            await self._handle_command(message, "websocket")
        elif message.get("type") == "disconnect":
            if message.get("reason") == "replaced":
                # Another connection owns this identity; replacement is not revocation.
                logger.warning("Agent connection replaced; stopping without deleting credentials")
                self._stop.set()
                return
            logger.warning("Control plane revoked this agent session: %s", message.get("reason", "unknown"))
            await self._revoke_local_credentials()
        elif message.get("type") == "tunnel_open":
            await self._open_shell(message.get("session_id", ""))
        elif message.get("type") == "tunnel_input":
            self._write_shell(message.get("session_id", ""), message.get("data", ""))
        elif message.get("type") == "tunnel_resize":
            self._resize_shell(
                message.get("session_id", ""), message.get("cols", 120), message.get("rows", 32)
            )
        elif message.get("type") == "tunnel_close":
            await self._close_shell(message.get("session_id", ""))

    async def _revoke_local_credentials(self) -> None:
        self.device_token = ""
        self.command_signing_key = ""
        self.provisioned = False
        try:
            self._save_state()
        except OSError:
            logger.exception("Could not clear credentials on disk; agent is stopping")
        await self._webrtc.close()
        for session_id in list(self._shells):
            await self._close_shell(session_id)
        self._stop.set()

    async def _open_shell(self, session_id: str) -> None:
        if not session_id or session_id in self._shells:
            return
        shell = await PtyShell.start()
        self._shells[session_id] = shell
        self._shell_readers[session_id] = asyncio.create_task(
            self._read_shell(session_id, shell)
        )
        await self._ws.send({"type": "tunnel_ready", "session_id": session_id})

    def _write_shell(self, session_id: str, data: str) -> None:
        shell = self._shells.get(session_id)
        if shell is None or not isinstance(data, str):
            return
        shell.write(data)

    def _resize_shell(self, session_id: str, columns: int, rows: int) -> None:
        shell = self._shells.get(session_id)
        if shell is not None:
            shell.resize(columns, rows)

    async def _read_shell(self, session_id: str, shell: PtyShell) -> None:
        try:
            while True:
                chunk = await shell.read()
                if not chunk:
                    break
                if self._ws and self._ws.connected:
                    await self._ws.send(
                        {
                            "type": "tunnel_output",
                            "session_id": session_id,
                            "data": chunk.decode("utf-8", errors="replace"),
                        }
                    )
        finally:
            if self._shells.get(session_id) is shell:
                self._shells.pop(session_id, None)
                self._shell_readers.pop(session_id, None)
                await shell.close()
                if self._ws and self._ws.connected:
                    await self._ws.send({"type": "tunnel_exit", "session_id": session_id})

    async def _close_shell(self, session_id: str) -> None:
        shell = self._shells.pop(session_id, None)
        reader = self._shell_readers.pop(session_id, None)
        if reader is not None and reader is not asyncio.current_task():
            reader.cancel()
        if shell is not None:
            await shell.close()

    def _on_mqtt_connect(self, client, userdata, flags, reason_code, properties=None) -> None:
        self.mqtt_connected = reason_code == 0
        if not self.mqtt_connected:
            return
        client.subscribe(f"{self.topic_prefix}/{self.device_id}/commands", qos=1)
        client.subscribe(f"{self.topic_prefix}/{self.device_id}/signals", qos=1)
        if self._loop is not None and not self._loop.is_closed():
            future = asyncio.run_coroutine_threadsafe(self._replay_results("mqtt"), self._loop)
            future.add_done_callback(self._observe_transport_callback)
        inventory = self._inventory()
        self._publish_event({"type": "hello", "payload": inventory})
        # Keep hardware data as an explicit event as well as part of hello and
        # heartbeat. This mirrors the main-branch inventory contract while
        # staying on the current Aitogy `/events` transport.
        self._publish_event({"type": "inventory", "payload": inventory})
        logger.info(
            "MQTT connected; %s",
            "WSS fallback is available" if self.provisioned else "awaiting UI provisioning",
        )

    def _on_mqtt_disconnect(self, client, userdata, disconnect_flags, reason_code, properties=None) -> None:
        self.mqtt_connected = False
        logger.warning("MQTT disconnected; WSS fallback remains active")

    def _on_mqtt_message(self, client, userdata, message) -> None:
        try:
            payload = json.loads(message.payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            logger.warning("Ignoring malformed MQTT message")
            return
        if not isinstance(payload, dict) or not isinstance(payload.get("payload", {}), dict):
            logger.warning("Ignoring MQTT message with invalid envelope")
            return
        if self._loop is not None and not self._loop.is_closed():
            future = asyncio.run_coroutine_threadsafe(
                self._handle_transport_message(payload), self._loop
            )
            future.add_done_callback(self._observe_transport_callback)

    @staticmethod
    def _observe_transport_callback(future) -> None:
        if future.cancelled():
            return
        try:
            future.result()
        except Exception:
            logger.exception("Agent command handling failed")

    async def _handle_transport_message(self, message: dict) -> None:
        if message.get("device_id") not in {None, self.device_id}:
            return
        if message.get("type") == "signal":
            await self._handle_signal(message.get("payload") or {}, "mqtt")
        elif message.get("type") == "command":
            await self._handle_command(message, "mqtt")

    async def _handle_signal(self, payload: dict, transport: str) -> None:
        token = self._signal_transport.set(transport)
        try:
            await self._webrtc.handle_signal(payload)
        finally:
            self._signal_transport.reset(token)

    async def _handle_command(self, message: dict, transport: str) -> None:
        if not hasattr(self, "_command_lock"):
            self._command_lock = asyncio.Lock()
        async with self._command_lock:
            try:
                await self._execute_command(message, transport)
            except OSError:
                logger.exception("Command journal write failed; preserving recovery intent")
                command_id = str(message.get("command_id", ""))
                # A committed intent may already have changed state. Do not emit a
                # false failure that would prevent recovery of its actual result.
                if not self._journal.seen(command_id):
                    await self._transmit_command_result(command_id,
                        {"ok": False, "error": "command storage unavailable"}, transport)

    async def _execute_command(self, message: dict, transport: str) -> None:
        command_type = str(message.get("command_type") or "")
        payload = message.get("payload") or {}
        verification_key = self.command_signing_key
        if command_type in {"device.provision", "provision_device"}:
            # The current device key is not available during first provisioning;
            # the one-time token is the bootstrap signing key for this command.
            verification_key = str(payload.get("device_token") or payload.get("token") or "").strip()
        if not _verify_command(message, verification_key):
            logger.warning("Rejected unsigned or invalid %s command", command_type or "unknown")
            return
        command_id = str(message.get("command_id", ""))
        if not command_id:
            return
        if self._journal.seen(command_id):
            result = self._journal.result(command_id)
            if result is None:
                if (command_type in {"device.provision", "provision_device"} and self.provisioned
                        and self.device_token == payload.get("device_token")
                        and self.command_signing_key == payload.get("command_signing_key")):
                    result = {"ok": True, "name": self.device_name, "provisioned": True}
                elif command_type == "device.rename" and self.device_name == payload.get("name"):
                    result = {"ok": True, "name": self.device_name}
                elif command_type == "device.revoke":
                    await self._revoke_local_credentials()
                    result = {"ok": True, "revoked": True}
                else:
                    result = {"ok": False, "error": "previous execution interrupted; result is unknown"}
            if result.get("ok") and command_type in {"device.rename", "device.provision", "provision_device"} and self._journal.result(command_id) is None:
                self._save_state()  # Confirm an interrupted generation before ACK.
            await self._send_command_result(command_id, result, transport)
            return
        if message.get("expires_at") and int(time.time()) >= int(message["expires_at"]):
            self._journal.add(command_id, message)
            await self._send_command_result(
                command_id, {"ok": False, "error": "command expired"}, transport
            )
            return
        self._journal.add(command_id, message)
        if command_type == "device.revoke":
            await self._revoke_local_credentials()
            await self._send_command_result(command_id, {"ok": True, "revoked": True}, transport)
            return
        previous_state = (self.device_name, self.device_token, self.command_signing_key, self.provisioned)
        try:
            if command_type in {"device.provision", "provision_device"}:
                name = str(payload.get("name") or "").strip()
                token = str(payload.get("device_token") or payload.get("token") or "").strip()
                command_signing_key = str(payload.get("command_signing_key") or "").strip()
                if not name or len(token) < 32 or not command_signing_key:
                    result = {"ok": False, "error": "name, device token and command key are required"}
                else:
                    self.device_name = name[:160]
                    self.device_token = token
                    self.command_signing_key = command_signing_key
                    self.provisioned = True
                    self._save_state()
                    await self._restart_websocket()
                    result = {"ok": True, "name": self.device_name, "provisioned": True}
            elif command_type == "device.rename":
                name = str(payload.get("name") or "").strip()
                if not self.provisioned or not name:
                    result = {"ok": False, "error": "device is not provisioned"}
                else:
                    self.device_name = name[:160]
                    self._save_state()
                    result = {"ok": True, "name": self.device_name}
            elif command_type in {"agent.info", "system.info"}:
                result = {"ok": True, **self._inventory()}
            elif command_type == "webrtc.signal":
                await self._handle_signal(payload, transport)
                result = {"ok": True}
            elif command_type == "ping":
                result = {"ok": True, "pong": int(time.time())}
            else:
                result = {"ok": False, "error": "unsupported command"}
        except AtomicCommitUncertain:
            # Keep the visible generation and the pending intent; never cache a
            # false failure after the filesystem's publication point.
            raise
        except OSError:
            self.device_name, self.device_token, self.command_signing_key, self.provisioned = previous_state
            logger.exception("Could not persist agent command state")
            result = {"ok": False, "error": "could not persist agent state; check disk space and permissions"}
        await self._send_command_result(command_id, result, transport)

    async def _replay_results(self, transport: str) -> None:
        # Resend durable ACKs on reconnect, including after process restart.
        for command_id, result in list(self._journal.entries.items()):
            if transport == "mqtt" and not self.mqtt_connected:
                break
            if transport == "websocket" and (not self._ws or not self._ws.connected):
                break
            if result is None:
                intent = self._journal.intents.get(command_id)
                if intent is None:
                    continue  # An old ID-only journal has no execution details.
                if intent.get("command_type") == "device.revoke" and not self.provisioned:
                    await self._send_command_result(command_id, {"ok": True, "revoked": True}, transport)
                else:
                    await self._handle_command(intent, transport)
            else:
                await self._transmit_command_result(command_id, result, transport)
            await asyncio.sleep(0.02)

    async def _send_command_result(
        self, command_id: str, result: dict, preferred_transport: str
    ) -> None:
        self._journal.complete(command_id, result)
        await self._transmit_command_result(command_id, result, preferred_transport)

    async def _transmit_command_result(self, command_id: str, result: dict, preferred_transport: str) -> None:
        response = {"type": "result", "command_id": command_id, "payload": result}
        if preferred_transport == "mqtt" and self.mqtt_connected:
            self._publish_event(response)
        elif preferred_transport == "websocket" and self._ws and self._ws.connected:
            await self._ws.send(response)
        elif self.mqtt_connected:
            self._publish_event(response)
        elif self._ws:
            await self._ws.send(response)

    async def _send_signal(self, payload: dict) -> None:
        message = {"type": "signal", "payload": payload}
        preferred_transport = self._signal_transport.get()
        if preferred_transport == "mqtt" and self.mqtt_connected:
            self._publish_event(message)
        elif preferred_transport == "websocket" and self._ws and self._ws.connected:
            await self._ws.send(message)
        elif self.mqtt_connected:
            self._publish_event(message)
        elif self._ws:
            await self._ws.send(message)

    def _publish_event(self, message: dict) -> None:
        self._mqtt.publish(
            f"{self.topic_prefix}/{self.device_id}/events",
            json.dumps(message, separators=(",", ":")),
            qos=1,
        )


def main() -> None:
    asyncio.run(Agent().run())


if __name__ == "__main__":
    main()
