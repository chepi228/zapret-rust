"""Disposable IPv4-loopback QUIC fixture. No system trust changes.

Requires optional aioquic/cryptography packages and a zapret_net unit-test binary.
The production client must reject the fixture's unknown CA. Successful h3 tests
use the unit-test-only loopback trust option, which is absent from release builds.
"""
import argparse
import asyncio
import datetime
import ipaddress
import json
import os
from pathlib import Path
import sys
import tempfile


def certificate(directory):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]), critical=False).sign(key, hashes.SHA256()))
    cert_file, key_file = directory / "fixture.crt", directory / "fixture.key"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    return cert_file, key_file


async def child(*command, env=None):
    process = await asyncio.create_subprocess_exec(
        *map(str, command), env=env, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE)
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), 20)
        assert process.returncode == 0, (stdout + stderr).decode(errors="replace")
        return stdout
    finally:
        if process.returncode is None:
            process.kill()
            await process.communicate()


async def fixture(args):
    from aioquic.asyncio import QuicConnectionProtocol, serve
    from aioquic.h3.connection import H3Connection, H3_ALPN
    from aioquic.h3.events import HeadersReceived
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.events import ProtocolNegotiated

    observed = []

    class Http3(QuicConnectionProtocol):
        h3 = None

        def quic_event_received(self, event):
            if isinstance(event, ProtocolNegotiated):
                self.h3 = H3Connection(self._quic)
            if self.h3:
                for message in self.h3.handle_event(event):
                    if isinstance(message, HeadersReceived):
                        headers = dict(message.headers)
                        observed.append((headers.get(b":method"), headers.get(b":path")))
                        path = headers[b":path"]
                        if path == b"/stall":
                            continue
                        status, extra = {
                            b"/denied": (b"403", []),
                            b"/redirect": (b"302", [(b"location", b"/denied")]),
                            b"/downgrade": (b"302", [(b"location", b"http://127.0.0.1:9/")]),
                        }.get(path, (b"200", []))
                        self.h3.send_headers(message.stream_id, [
                            (b":status", status), (b"content-length", b"0"), *extra,
                        ], end_stream=True)
                        self.transmit()

    with tempfile.TemporaryDirectory(prefix="zapret-http3-fixture-") as temporary:
        cert, key = certificate(Path(temporary))
        config = QuicConfiguration(is_client=False, alpn_protocols=H3_ALPN)
        config.load_cert_chain(cert, key)
        server = await serve("127.0.0.1", 0, configuration=config, create_protocol=Http3)
        port = server._transport.get_extra_info("sockname")[1]
        env = {**os.environ, "ZAPRET_HTTP3_FIXTURE_PORT": str(port)}
        try:
            if args.probe:
                root = Path(__file__).resolve().parents[3]
                options = {"url": f"https://127.0.0.1:{port}/", "modes": ["Http3"],
                           "timeout_ms": 3000, "browser_path": ""}
                result = json.loads(await child(
                    args.probe, "--diagnostics", "webcheck", root, json.dumps(options)))
                assert result["capabilities"]["native_http3"] is True
                row = result["rows"][0]
                assert row["reason"] == "TlsFailure", row
                assert not row["quic_confirmed"] and not row["complete"], row
                print("Production HTTP/3 client rejected the unknown CA", flush=True)
            output = await child(
                args.test_binary, "--ignored",
                "winhttp::tests::loopback_http3_refuses_unknown_certificate_and_reports_confirmed_headers",
                "--nocapture", env=env)
            print(output.decode(errors="replace"), end="", flush=True)
            assert b"1 passed" in output, "The requested unit test was not executed"
            assert observed and all(method == b"HEAD" for method, _ in observed), observed
            assert {b"/", b"/redirect", b"/denied", b"/downgrade", b"/stall"} <= {
                path for _, path in observed}, observed
            print("PASS: h3 headers, certificate rejection, redirects, deadline and subsequent request")
        finally:
            server.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test-binary", type=Path, required=True)
    parser.add_argument("--probe", type=Path)
    parser.add_argument("--dependencies", type=Path)
    args = parser.parse_args()
    if args.dependencies:
        sys.path.insert(0, str(args.dependencies.resolve()))
    args.test_binary = args.test_binary.resolve(strict=True)
    if args.probe:
        args.probe = args.probe.resolve(strict=True)
    asyncio.run(fixture(args))
