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
import signal
import socket
import shutil
import time
from collections import deque
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote
from urllib.request import Request, urlopen

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
    "AITOGY_MQTT_HOST": "mqtt.aitogy.asia",
    "AITOGY_MQTT_PORT": "8883",
    "AITOGY_MQTT_TLS": "true",
    "AITOGY_MQTT_USERNAME": "mqttUser",
    "AITOGY_MQTT_PASSWORD": "MqttPassword123$%^",
    "AITOGY_MQTT_TOPIC_PREFIX": "aitogy/devices",
    "AITOGY_STUN_URLS": "stun:aitogy.asia:3478",
    "AITOGY_TURN_URLS": "turn:aitogy.asia:3478?transport=udp,turns:aitogy.asia:5349?transport=tcp",
    "AITOGY_TURN_TTL_SECONDS": "3600",
}.items():
    os.environ.setdefault(_name, _value)
logging.basicConfig(level=os.getenv("AITOGY_LOG_LEVEL", "INFO"))
logger = logging.getLogger("agent")

_ARM_CPU_MODELS = {
    ("0x41", "0xd03"): "Cortex-A53",
    ("0x41", "0xd08"): "Cortex-A72",
    ("0x41", "0xd0b"): "Cortex-A76",
}
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
    default = Path("/var/lib/agent_connect") if os.name != "nt" else Path(".agent-connect")
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
            candidate = value.strip()
            if not candidate.isdecimal():
                return candidate
    return ""


def _cpu_model() -> str:
    fields: dict[str, str] = {}
    for line in _read_text("/proc/cpuinfo", 32768).splitlines():
        key, separator, value = line.partition(":")
        if separator:
            fields[key.strip().lower()] = value.strip()
    model_name = fields.get("model name") or fields.get("processor")
    if model_name and not model_name.isdecimal():
        return model_name
    implementer = fields.get("cpu implementer", "").lower()
    part = fields.get("cpu part", "").lower()
    if (implementer, part) in _ARM_CPU_MODELS:
        return _ARM_CPU_MODELS[(implementer, part)]
    hardware = fields.get("hardware", "").lower()
    return _RPI_SOC_CPU_MODELS.get(hardware, hardware or "")


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
    model = _read_text("/proc/device-tree/model") or _read_text("/sys/firmware/devicetree/base/model")
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
        "os_pretty_name": os_release.get("PRETTY_NAME"),
        "os_id": os_release.get("ID"),
        "os_id_like": os_release.get("ID_LIKE"),
        "os_version": os_release.get("VERSION_ID"),
        "kernel_version": platform.release() or None,
        "collected_at": datetime.now(timezone.utc).isoformat(),
    }


class CommandJournal:
    """Small durable dedupe journal for QoS1/WSS redelivery after restart."""

    def __init__(self, path: Path, limit: int = 512) -> None:
        self.path = path
        self.items: deque[str] = deque(maxlen=limit)
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
            self.items.extend(str(item) for item in loaded if item)
        except (FileNotFoundError, OSError, ValueError, TypeError):
            pass

    def seen(self, command_id: str) -> bool:
        return command_id in self.items

    def add(self, command_id: str) -> None:
        self.items.append(command_id)
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self.path.with_suffix(".tmp")
            temporary.write_text(json.dumps(list(self.items)), encoding="utf-8")
            os.replace(temporary, self.path)
            if os.name == "posix":
                self.path.chmod(0o600)
        except OSError as error:  # pragma: no cover - filesystem dependent
            logger.warning("Could not persist command journal: %s", error)


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

    def __init__(self, url: str, on_message: MessageHandler) -> None:
        self.url = url
        self.on_message = on_message
        self._outbox: asyncio.Queue[dict] = asyncio.Queue()
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
                    done, pending = await asyncio.wait(
                        {sender, receiver}, return_when=asyncio.FIRST_COMPLETED
                    )
                    for task in pending:
                        task.cancel()
                    for task in done:
                        task.result()
            except asyncio.CancelledError:
                raise
            except Exception as error:  # pragma: no cover - network dependent
                logger.warning("Agent WSS unavailable: %s", error)
            finally:
                self.connected = False
                self._socket = None
            if not self._stop.is_set():
                await asyncio.sleep(delay)
                delay = min(delay * 2, 30)

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
        self._state = self._load_state()
        self.device_id = os.getenv("AITOGY_DEVICE_ID") or self._state.get("device_id") or _default_device_id()
        self.device_name = str(self._state.get("name") or "").strip()
        legacy_token = str(self._state.get("device_token") or "").strip()
        legacy_command_key = str(self._state.get("command_signing_key") or "").strip()
        self.device_token = _read_text(str(self.token_path), 4096) or legacy_token
        self.command_signing_key = _read_text(str(self.command_key_path), 4096) or legacy_command_key
        self.provisioned = bool(self.device_token and self.command_signing_key)
        if legacy_token or legacy_command_key:
            # Migrate older installs once; future state writes never contain secrets.
            self._save_state()
        self.topic_prefix = os.getenv("AITOGY_MQTT_TOPIC_PREFIX", "aitogy/devices")
        self.mqtt_connected = False
        self._loop: asyncio.AbstractEventLoop | None = None
        self._stop = asyncio.Event()
        self._signal_transport = contextvars.ContextVar("signal_transport", default=None)
        default_journal = self.state_dir / "commands.json"
        self._journal = CommandJournal(
            Path(os.getenv("AITOGY_COMMAND_JOURNAL", default_journal))
        )
        self._ws: AitogyWebSocketControl | None = None
        self._ws_task: asyncio.Task | None = None
        self._shells: dict[str, PtyShell] = {}
        self._shell_readers: dict[str, asyncio.Task] = {}
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
        self._mqtt.enable_logger(logger)
        self._mqtt.reconnect_delay_set(min_delay=1, max_delay=30)
        self._mqtt.on_connect = self._on_mqtt_connect
        self._mqtt.on_disconnect = self._on_mqtt_disconnect
        self._mqtt.on_message = self._on_mqtt_message
        username = os.getenv("AITOGY_MQTT_USERNAME")
        if username:
            self._mqtt.username_pw_set(username, os.getenv("AITOGY_MQTT_PASSWORD"))
        if _env_bool("AITOGY_MQTT_TLS", True):
            self._mqtt.tls_set(ca_certs=os.getenv("AITOGY_MQTT_CA_FILE") or None)

    def _load_state(self) -> dict:
        try:
            loaded = json.loads(self.state_path.read_text(encoding="utf-8"))
            return loaded if isinstance(loaded, dict) else {}
        except (FileNotFoundError, OSError, ValueError, TypeError):
            return {}

    def _save_state(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        _write_secret(self.token_path, self.device_token)
        _write_secret(self.command_key_path, self.command_signing_key)
        payload = {
            "device_id": self.device_id,
            "name": self.device_name,
            "provisioned": bool(self.provisioned and self.device_token and self.command_signing_key),
        }
        temporary = self.state_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        os.replace(temporary, self.state_path)
        if os.name == "posix":
            self.state_path.chmod(0o600)

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
        except Exception as error:  # pragma: no cover - network dependent
            logger.warning("Pairing request failed: %s", error)
            return False
        device_token = str(result.get("device_token") or "").strip()
        command_signing_key = str(result.get("command_signing_key") or "").strip()
        if len(device_token) < 32 or not command_signing_key:
            logger.warning("Pairing response did not include device credentials")
            return False
        self.device_token = device_token
        self.command_signing_key = command_signing_key
        self.device_name = str(result.get("name") or os.getenv("AITOGY_DEVICE_NAME", "").strip() or socket.gethostname())[:160]
        self.provisioned = True
        self._save_state()
        pairing_file = self.state_dir / "pairing.token"
        try:
            pairing_file.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            logger.warning("Could not remove consumed pairing token file")
        logger.info("Agent paired as %s", self.device_name)
        return True

    def _start_websocket(self) -> None:
        if not self._loop or self._ws_task or not self.device_token:
            return
        self._ws = AitogyWebSocketControl(self._ws_url(), self._handle_ws_message)
        self._ws_task = asyncio.create_task(self._ws.run())

    async def _restart_websocket(self) -> None:
        previous = self._ws
        self._ws = None
        self._ws_task = None
        if previous is not None:
            await previous.close()
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
        if not self.provisioned:
            await asyncio.to_thread(self._pair_with_control_plane)
        self._mqtt.connect_async(
            os.getenv("AITOGY_MQTT_HOST", "mqtt.aitogy.asia"),
            int(os.getenv("AITOGY_MQTT_PORT", "8883")),
            60,
        )
        self._mqtt.loop_start()
        self._start_websocket()
        heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        try:
            await self._stop.wait()
        finally:
            if self._ws_task:
                self._ws_task.cancel()
            heartbeat_task.cancel()
            await asyncio.gather(self._ws_task, heartbeat_task, return_exceptions=True)
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
            await asyncio.sleep(30)

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
            "agent_version": os.getenv("AITOGY_AGENT_VERSION", "1.0.0"),
            "capabilities": {"webrtc": True, "shell": True, "screen": False},
            "status": "online" if self.provisioned else "unprovisioned",
            "provisioned": self.provisioned,
            "token_fingerprint": token_fingerprint,
            "sent_at": int(time.time()),
        }

    async def _handle_ws_message(self, message: dict) -> None:
        if message.get("type") == "signal":
            await self._handle_signal(message.get("payload") or {}, "websocket")
        elif message.get("type") == "command":
            await self._handle_command(message, "websocket")
        elif message.get("type") == "disconnect":
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
        self._save_state()
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
        self._publish_event({"type": "hello", "payload": self._inventory()})
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
        if self._loop is not None:
            asyncio.run_coroutine_threadsafe(
                self._handle_transport_message(payload), self._loop
            )

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
        if not command_id or self._journal.seen(command_id):
            return
        if message.get("expires_at") and int(time.time()) >= int(message["expires_at"]):
            self._journal.add(command_id)
            await self._send_command_result(
                command_id, {"ok": False, "error": "command expired"}, transport
            )
            return
        self._journal.add(command_id)
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
        elif command_type == "device.revoke":
            result = {"ok": True, "revoked": True}
            await self._send_command_result(command_id, result, transport)
            await self._revoke_local_credentials()
            return
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
        await self._send_command_result(command_id, result, transport)

    async def _send_command_result(
        self, command_id: str, result: dict, preferred_transport: str
    ) -> None:
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
