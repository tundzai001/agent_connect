"""Single-file Linux agent for MQTT control, WSS fallback and WebRTC shell."""

import asyncio
import base64
import contextvars
import hashlib
import hmac
import json
import logging
import os
import platform
import signal
import socket
import time
from collections import deque
from collections.abc import Awaitable, Callable
from pathlib import Path
from urllib.parse import quote

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


def _env_bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).lower() in {"1", "true", "yes", "on"}


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
        self._processes = set()

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
        process = await asyncio.create_subprocess_exec(
            "/bin/bash",
            "-l",
            "-i",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        self._processes.add(process)

        @channel.on("message")
        def on_message(data) -> None:
            if process.stdin is None:
                return
            raw = data.encode() if isinstance(data, str) else data
            process.stdin.write(raw)
            asyncio.create_task(process.stdin.drain())

        try:
            while channel.readyState == "open":
                if process.stdout is None:
                    break
                chunk = await process.stdout.read(4096)
                if not chunk:
                    break
                channel.send(chunk.decode("utf-8", errors="replace"))
        finally:
            if process.returncode is None:
                process.terminate()
                await process.wait()
            self._processes.discard(process)
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
        for process in list(self._processes):
            if process.returncode is None:
                process.terminate()

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
        self.device_id = os.getenv("AITOGY_DEVICE_ID") or _default_device_id()
        self.topic_prefix = os.getenv("AITOGY_MQTT_TOPIC_PREFIX", "aitogy/devices")
        self.mqtt_connected = False
        self._loop: asyncio.AbstractEventLoop | None = None
        self._stop = asyncio.Event()
        self._signal_transport = contextvars.ContextVar("signal_transport", default=None)
        default_journal = (
            "/var/lib/edge-agent/commands.json"
            if os.name != "nt"
            else ".agent-command-journal.json"
        )
        self._journal = CommandJournal(
            Path(os.getenv("AITOGY_COMMAND_JOURNAL", default_journal))
        )
        self._ws = AitogyWebSocketControl(self._ws_url(), self._handle_ws_message)
        self._shells: dict[str, asyncio.subprocess.Process] = {}
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
        self._mqtt = mqtt.Client(client_id=f"agent-{self.device_id}")
        self._mqtt.reconnect_delay_set(min_delay=1, max_delay=30)
        self._mqtt.on_connect = self._on_mqtt_connect
        self._mqtt.on_disconnect = self._on_mqtt_disconnect
        self._mqtt.on_message = self._on_mqtt_message
        username = os.getenv("AITOGY_MQTT_USERNAME")
        if username:
            self._mqtt.username_pw_set(username, os.getenv("AITOGY_MQTT_PASSWORD"))
        if _env_bool("AITOGY_MQTT_TLS", True):
            self._mqtt.tls_set(ca_certs=os.getenv("AITOGY_MQTT_CA_FILE") or None)

    def _ws_url(self) -> str:
        configured = os.getenv("AITOGY_AGENT_WS_URL", "").rstrip("/")
        if configured:
            base = configured
        else:
            base = os.getenv("AITOGY_CONTROL_URL", "https://connect.aitogy.com").rstrip("/")
            base = base.replace("https://", "wss://").replace("http://", "ws://")
            base += "/ws/agent"
        token_secret = os.getenv("AITOGY_AGENT_WS_SECRET", "")
        token = (
            hmac.new(
                token_secret.encode(), self.device_id.encode(), hashlib.sha256
            ).hexdigest()
            if token_secret
            else ""
        )
        return f"{base}/{quote(self.device_id, safe='')}?token={quote(token)}"

    async def run(self) -> None:
        self._loop = asyncio.get_running_loop()
        for signum in (signal.SIGINT, signal.SIGTERM):
            try:
                self._loop.add_signal_handler(signum, self._stop.set)
            except (NotImplementedError, RuntimeError):
                pass
        self._mqtt.connect_async(
            os.getenv("AITOGY_MQTT_HOST", "aitogy.asia"),
            int(os.getenv("AITOGY_MQTT_PORT", "8883")),
            60,
        )
        self._mqtt.loop_start()
        ws_task = asyncio.create_task(self._ws.run())
        heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        await self._ws.send({"type": "hello", "payload": self._inventory()})
        try:
            await self._stop.wait()
        finally:
            ws_task.cancel()
            heartbeat_task.cancel()
            await asyncio.gather(ws_task, heartbeat_task, return_exceptions=True)
            await self._webrtc.close()
            for session_id in list(self._shells):
                await self._close_shell(session_id)
            await self._ws.close()
            self._mqtt.loop_stop()
            self._mqtt.disconnect()

    async def _heartbeat_loop(self) -> None:
        while True:
            message = {"type": "heartbeat", "payload": self._inventory()}
            if self.mqtt_connected:
                self._publish_event(message)
            if self._ws.connected:
                await self._ws.send(message)
            await asyncio.sleep(30)

    def _inventory(self) -> dict:
        return {
            "hostname": socket.gethostname(),
            "platform": platform.system().lower(),
            "architecture": platform.machine(),
            "agent_version": os.getenv("AITOGY_AGENT_VERSION", "1.0.0"),
            "capabilities": {"webrtc": True, "shell": True, "screen": False},
            "sent_at": int(time.time()),
        }

    async def _handle_ws_message(self, message: dict) -> None:
        if message.get("type") == "signal":
            await self._handle_signal(message.get("payload") or {}, "websocket")
        elif message.get("type") == "command":
            await self._handle_command(message, "websocket")
        elif message.get("type") == "tunnel_open":
            await self._open_shell(message.get("session_id", ""))
        elif message.get("type") == "tunnel_input":
            self._write_shell(message.get("session_id", ""), message.get("data", ""))
        elif message.get("type") == "tunnel_close":
            await self._close_shell(message.get("session_id", ""))

    async def _open_shell(self, session_id: str) -> None:
        if not session_id or session_id in self._shells:
            return
        process = await asyncio.create_subprocess_exec(
            "/bin/bash",
            "-l",
            "-i",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        self._shells[session_id] = process
        self._shell_readers[session_id] = asyncio.create_task(
            self._read_shell(session_id, process)
        )
        await self._ws.send({"type": "tunnel_ready", "session_id": session_id})

    def _write_shell(self, session_id: str, data: str) -> None:
        process = self._shells.get(session_id)
        if process is None or process.stdin is None or not isinstance(data, str):
            return
        process.stdin.write(data[:65536].encode())
        asyncio.create_task(process.stdin.drain())

    async def _read_shell(self, session_id: str, process: asyncio.subprocess.Process) -> None:
        try:
            while process.stdout is not None:
                chunk = await process.stdout.read(4096)
                if not chunk:
                    break
                await self._ws.send(
                    {
                        "type": "tunnel_output",
                        "session_id": session_id,
                        "data": chunk.decode("utf-8", errors="replace"),
                    }
                )
        finally:
            if self._shells.get(session_id) is process:
                self._shells.pop(session_id, None)
                self._shell_readers.pop(session_id, None)
                await self._ws.send({"type": "tunnel_exit", "session_id": session_id})

    async def _close_shell(self, session_id: str) -> None:
        process = self._shells.pop(session_id, None)
        reader = self._shell_readers.pop(session_id, None)
        if reader is not None and reader is not asyncio.current_task():
            reader.cancel()
        if process is not None and process.returncode is None:
            process.terminate()
            await process.wait()

    def _on_mqtt_connect(self, client, userdata, flags, return_code, *extra) -> None:
        self.mqtt_connected = return_code == 0
        if not self.mqtt_connected:
            return
        client.subscribe(f"{self.topic_prefix}/{self.device_id}/commands", qos=1)
        client.subscribe(f"{self.topic_prefix}/{self.device_id}/signals", qos=1)
        self._publish_event({"type": "hello", "payload": self._inventory()})
        logger.info("MQTT connected; WSS remains available as fallback/signaling path")

    def _on_mqtt_disconnect(self, client, userdata, return_code, *extra) -> None:
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
        command_id = str(message.get("command_id", ""))
        if not command_id or self._journal.seen(command_id):
            return
        self._journal.add(command_id)
        if message.get("expires_at") and int(time.time()) >= int(message["expires_at"]):
            await self._send_command_result(
                command_id, {"ok": False, "error": "command expired"}, transport
            )
            return
        command_type = message.get("command_type", "")
        payload = message.get("payload") or {}
        if command_type in {"agent.info", "system.info"}:
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
        elif preferred_transport == "websocket" and self._ws.connected:
            await self._ws.send(response)
        elif self.mqtt_connected:
            self._publish_event(response)
        else:
            await self._ws.send(response)

    async def _send_signal(self, payload: dict) -> None:
        message = {"type": "signal", "payload": payload}
        preferred_transport = self._signal_transport.get()
        if preferred_transport == "mqtt" and self.mqtt_connected:
            self._publish_event(message)
        elif preferred_transport == "websocket" and self._ws.connected:
            await self._ws.send(message)
        elif self.mqtt_connected:
            self._publish_event(message)
        else:
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
