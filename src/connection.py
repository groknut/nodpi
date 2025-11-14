

import asyncio
from abc import ABC, abstractmethod
import traceback
from typing import Tuple, List, Dict
from logger import ILogger
from statistic import IStatistics
from datetime import datetime
from config import ProxyConfig
import random
from blacklist_manager import NoBlacklistManager, AutoBlacklistManager, IBlacklistManager

class ConnectionInfo:
    """Class to store connection information"""

    def __init__(self, src_ip: str, dst_domain: str, method: str):

        self.src_ip = src_ip
        self.dst_domain = dst_domain
        self.method = method
        self.start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.traffic_in = 0
        self.traffic_out = 0

class IConnectionHandler(ABC):
    """Interface for connection handling"""

    @abstractmethod
    async def handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Handle incoming connection"""


class ConnectionHandler(IConnectionHandler):
    """Handles individual client connections"""

    def __init__(
        self,
        config: ProxyConfig,
        blacklist_manager: IBlacklistManager,
        statistics: IStatistics,
        logger: ILogger,
    ):

        self.config = config
        self.blacklist_manager = blacklist_manager
        self.statistics = statistics
        self.logger = logger
        self.out_host = self.config.out_host
        self.active_connections: Dict[Tuple, ConnectionInfo] = {}
        self.connections_lock = asyncio.Lock()
        self.tasks: List[asyncio.Task] = []
        self.tasks_lock = asyncio.Lock()

    async def handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Handle incoming client connection"""

        try:
            client_ip, client_port = writer.get_extra_info("peername")
            http_data = await reader.read(1500)

            if not http_data:
                writer.close()
                return

            method, host, port = self._parse_http_request(http_data)
            conn_key = (client_ip, client_port)
            conn_info = ConnectionInfo(
                client_ip, host.decode(), method.decode())

            if method == b"CONNECT" and isinstance(
                self.blacklist_manager, AutoBlacklistManager
            ):
                await self.blacklist_manager.check_domain(host)

            async with self.connections_lock:
                self.active_connections[conn_key] = conn_info

            self.statistics.update_traffic(0, len(http_data))
            conn_info.traffic_out += len(http_data)

            if method == b"CONNECT":
                await self._handle_https_connection(
                    reader, writer, host, port, conn_key, conn_info
                )
            else:
                await self._handle_http_connection(
                    reader, writer, http_data, host, port, conn_key
                )

        except Exception:
            await self._handle_connection_error(writer, conn_key)

    def _parse_http_request(self, http_data: bytes) -> Tuple[bytes, bytes, int]:
        """Parse HTTP request to extract method, host and port"""

        headers = http_data.split(b"\r\n")
        first_line = headers[0].split(b" ")
        method = first_line[0]
        url = first_line[1]

        if method == b"CONNECT":
            host_port = url.split(b":")
            host = host_port[0]
            port = int(host_port[1]) if len(host_port) > 1 else 443
        else:
            host_header = next(
                (h for h in headers if h.startswith(b"Host: ")), None)
            if not host_header:
                raise ValueError("Missing Host header")

            host_port = host_header[6:].split(b":")
            host = host_port[0]
            port = int(host_port[1]) if len(host_port) > 1 else 80

        return method, host, port

    async def _handle_https_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        host: bytes,
        port: int,
        conn_key: Tuple,
        conn_info: ConnectionInfo,
    ) -> None:
        """Handle HTTPS CONNECT request"""

        response_size = len(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        self.statistics.update_traffic(response_size, 0)
        conn_info.traffic_in += response_size

        remote_reader, remote_writer = await asyncio.open_connection(
            host.decode(), port, local_addr=(self.out_host, 0) if self.out_host else None
        )

        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()

        await self._handle_initial_tls_data(reader, remote_writer, host, conn_info)

        await self._setup_piping(reader, writer, remote_reader, remote_writer, conn_key)

    async def _handle_http_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        http_data: bytes,
        host: bytes,
        port: int,
        conn_key: Tuple,
    ) -> None:
        """Handle HTTP request"""

        remote_reader, remote_writer = await asyncio.open_connection(
            host.decode(), port, local_addr=(self.out_host, 0) if self.out_host else None
        )

        remote_writer.write(http_data)
        await remote_writer.drain()

        self.statistics.increment_total_connections()
        self.statistics.increment_allowed_connections()

        await self._setup_piping(reader, writer, remote_reader, remote_writer, conn_key)

    def _extract_sni_position(self, data):
        i = 0
        while i < len(data) - 8:
            if all(data[i + j] == 0x00 for j in [0, 1, 2, 4, 6, 7]):
                ext_len = data[i+3]
                server_name_list_len = data[i+5]
                server_name_len = data[i+8]
                if ext_len - server_name_list_len == 2 and server_name_list_len - server_name_len == 3:
                    sni_start = i + 9
                    sni_end = sni_start + server_name_len
                    return sni_start, sni_end
            i += 1
        return None

    async def _handle_initial_tls_data(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        host: bytes,
        conn_info: ConnectionInfo,
    ) -> None:
        """Handle initial TLS data and fragmentation"""

        try:
            head = await reader.read(5)
            data = await reader.read(2048)
        except Exception:
            self.logger.log_error(
                f"{host.decode()} : {traceback.format_exc()}")
            return

        should_fragment = True
        if not isinstance(self.blacklist_manager, NoBlacklistManager):
            should_fragment = self.blacklist_manager.is_blocked(
                conn_info.dst_domain)

        if not should_fragment:
            self.statistics.increment_total_connections()
            self.statistics.increment_allowed_connections()
            combined_data = head + data
            writer.write(combined_data)
            await writer.drain()

            self.statistics.update_traffic(0, len(combined_data))
            conn_info.traffic_out += len(combined_data)
            return

        self.statistics.increment_total_connections()
        self.statistics.increment_blocked_connections()

        parts = []

        if self.config.fragment_method == "sni":
            sni_pos = self._extract_sni_position(data)

            if sni_pos:
                part_start = data[:sni_pos[0]]
                sni_data = data[sni_pos[0]:sni_pos[1]]
                part_end = data[sni_pos[1]:]
                middle = (len(sni_data) + 1) // 2

                parts.append(
                    bytes.fromhex("160304") +
                    len(part_start).to_bytes(2, "big") +
                    part_start
                )
                parts.append(
                    bytes.fromhex("160304") +
                    len(sni_data[:middle]).to_bytes(2, "big") +
                    sni_data[:middle]
                )
                parts.append(
                    bytes.fromhex("160304") +
                    len(sni_data[middle:]).to_bytes(2, "big") +
                    sni_data[middle:]
                )
                parts.append(
                    bytes.fromhex("160304") +
                    len(part_end).to_bytes(2, "big") +
                    part_end
                )

        elif self.config.fragment_method == "random":
            host_end = data.find(b"\x00")
            if host_end != -1:
                part_data = (
                    bytes.fromhex("160304")
                    + (host_end + 1).to_bytes(2, "big")
                    + data[: host_end + 1]
                )
                parts.append(part_data)
                data = data[host_end + 1:]

            while data:
                chunk_len = random.randint(1, len(data))
                part_data = (
                    bytes.fromhex("160304")
                    + chunk_len.to_bytes(2, "big")
                    + data[:chunk_len]
                )
                parts.append(part_data)
                data = data[chunk_len:]

        combined_parts = b"".join(parts)
        writer.write(combined_parts)
        await writer.drain()

        self.statistics.update_traffic(0, len(combined_parts))
        conn_info.traffic_out += len(combined_parts)

    async def _setup_piping(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        remote_reader: asyncio.StreamReader,
        remote_writer: asyncio.StreamWriter,
        conn_key: Tuple,
    ) -> None:
        """Setup bidirectional piping between client and remote"""

        async with self.tasks_lock:
            self.tasks.extend(
                [
                    asyncio.create_task(
                        self._pipe_data(
                            client_reader, remote_writer, "out", conn_key)
                    ),
                    asyncio.create_task(
                        self._pipe_data(
                            remote_reader, client_writer, "in", conn_key)
                    ),
                ]
            )

    async def _pipe_data(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        direction: str,
        conn_key: Tuple,
    ) -> None:
        """Pipe data between reader and writer"""

        try:
            while not reader.at_eof() and not writer.is_closing():
                data = await reader.read(1500)
                if not data:
                    break

                if direction == "out":
                    self.statistics.update_traffic(0, len(data))
                else:
                    self.statistics.update_traffic(len(data), 0)

                async with self.connections_lock:
                    conn_info = self.active_connections.get(conn_key)
                    if conn_info:
                        if direction == "out":
                            conn_info.traffic_out += len(data)
                        else:
                            conn_info.traffic_in += len(data)

                writer.write(data)
                await writer.drain()
        except asyncio.CancelledError:
            pass
        except Exception:
            self.logger.log_error(
                f"{conn_info.dst_domain} : {traceback.format_exc()}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

            async with self.connections_lock:
                conn_info = self.active_connections.pop(conn_key, None)
                if conn_info:
                    self.logger.log_access(
                        f"{conn_info.start_time} {conn_info.src_ip} {conn_info.method} {conn_info.dst_domain} {conn_info.traffic_in} {conn_info.traffic_out}"
                    )

    async def _handle_connection_error(
        self, writer: asyncio.StreamWriter, conn_key: Tuple
    ) -> None:
        """Handle connection errors"""

        try:
            error_response = b"HTTP/1.1 500 Internal Server Error\r\n\r\n"
            writer.write(error_response)
            await writer.drain()

            self.statistics.update_traffic(len(error_response), 0)
        except Exception:
            pass

        async with self.connections_lock:
            conn_info = self.active_connections.pop(conn_key, None)

        self.statistics.increment_total_connections()
        self.statistics.increment_error_connections()
        self.logger.log_error(
            f"{conn_info.dst_domain} : {traceback.format_exc()}")

        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

    async def cleanup_tasks(self) -> None:
        """Clean up completed tasks"""

        while True:
            await asyncio.sleep(60)
            async with self.tasks_lock:
                self.tasks = [t for t in self.tasks if not t.done()]
