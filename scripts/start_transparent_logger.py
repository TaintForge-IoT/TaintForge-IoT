import argparse
import asyncio
from pathlib import Path

from taintforge_env.transparent_logger import run_transparent_logger
from taintforge_env.network_runtime import run_network_service


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--log-dir", required=True)
    parser.add_argument("--tcp-bind-ip", default="127.0.0.1")
    parser.add_argument("--tcp-port", type=int, default=40000)
    parser.add_argument("--udp-bind-ip", default="127.0.0.1")
    parser.add_argument("--udp-port", type=int, default=40001)
    parser.add_argument("--runtime", type=Path)
    args = parser.parse_args()

    asyncio.run(
        run_network_service(lambda: run_transparent_logger(
            log_dir=args.log_dir,
            tcp_bind_ip=args.tcp_bind_ip,
            tcp_bind_port=args.tcp_port,
            udp_bind_ip=args.udp_bind_ip,
            udp_bind_port=args.udp_port,
        ), log_dir=args.log_dir, runtime_path=args.runtime)
    )


if __name__ == "__main__":
    main()
