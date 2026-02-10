import getpass
import json
from typing import Annotated, Optional

import jwt
import typer
from rich import print

from pytune.device.android import Android
from pytune.device.device import Device
from pytune.device.linux import Linux
from pytune.device.windows import Windows
from pytune.utils.logger import Logger
from pytune.utils.utils import deviceauth, gettokens, prtauth

version = "1.2"
banner = (
    r"""
 ______   __  __     ______   __  __     __   __     ______    
/\  == \ /\ \_\ \   /\__  _\ /\ \/\ \   /\ "-.\ \   /\  ___\   
\ \  _-/ \ \____ \  \/_/\ \/ \ \ \_\ \  \ \ \-.  \  \ \  __\   
 \ \_\    \/\_____\    \ \_\  \ \_____\  \ \_\\"\_\  \ \_____\ 
  \/_/     \/_____/     \/_/   \/_____/   \/_/ \/_/   \/_____/ 
                                                               
"""
    + f"      Faking a device to Microsoft Intune (version:{version})"
)

app = typer.Typer(
    rich_markup_mode="rich",
    add_completion=False,
)


# Global state for context
class Context:
    def __init__(self):
        self.logger: Optional[Logger] = None
        self.proxy: Optional[dict] = None


ctx = Context()


def version_callback(value: bool):
    if value:
        typer.echo(f"pytune version {version}")
        raise typer.Exit()


@app.callback()
def main(
    proxy: Annotated[
        Optional[str],
        typer.Option(
            "-x",
            "--proxy",
            help="proxy to be used during authentication (format: http://proxyip:port)",
        ),
    ] = None,
    verbose: Annotated[
        bool, typer.Option("-v", "--verbose", help="show information for debugging")
    ] = False,
    version_flag: Annotated[
        Optional[bool],
        typer.Option(
            "--version", callback=version_callback, help="Show version and exit"
        ),
    ] = None,
):
    """
    Pytune commands
    """
    ctx.logger = Logger(verbose)
    print(banner)

    if proxy:
        ctx.proxy = {"https": proxy, "http": proxy}


class Pytune:
    def __init__(self, logger):
        self.logger = logger

    def load_tokenfile(self, tokenfile):
        try:
            with open(tokenfile, "r") as f:
                data = json.load(f)
        except:
            self.logger.error("failed to load token file")
        return data

    def get_password(self, password):
        if password is None:
            password = getpass.getpass("Enter your password: ")
        return password

    def new_device(
        self, os, device_name, username, password, refresh_token, certpfx, proxy
    ):
        prt = None
        session_key = None
        tenant = None
        deviceid = None
        uid = None

        if certpfx:
            if refresh_token is None:
                password = self.get_password(password)
            prt, session_key = deviceauth(
                username, password, refresh_token, certpfx, proxy
            )
            access_token, refresh_token = prtauth(
                prt,
                session_key,
                "29d9ed98-a469-4536-ade2-f981bc1d605e",
                "https://enrollment.manage.microsoft.com/",
                "ms-appx-web://Microsoft.AAD.BrokerPlugin/DRS",
                proxy,
            )
            claims = jwt.decode(
                access_token, options={"verify_signature": False}, algorithms=["RS256"]
            )
            tenant = claims["upn"].split("@")[1]
            deviceid = claims["deviceid"]
            uid = claims["oid"]

        if os == "Android":
            device = Android(
                self.logger,
                os,
                device_name,
                deviceid,
                uid,
                tenant,
                prt,
                session_key,
                proxy,
            )
        elif os == "Windows":
            device = Windows(
                self.logger,
                os,
                device_name,
                deviceid,
                uid,
                tenant,
                prt,
                session_key,
                proxy,
            )
        elif os == "Linux":
            device = Linux(
                self.logger,
                os,
                device_name,
                deviceid,
                uid,
                tenant,
                prt,
                session_key,
                proxy,
            )
        return device

    def entra_join(
        self,
        username,
        password,
        access_token,
        tokenfile,
        device_name,
        os,
        deviceticket,
        proxy,
    ):
        device = self.new_device(os, device_name, None, None, None, None, proxy)

        if tokenfile:
            access_token = self.load_tokenfile(tokenfile).get("accessToken")

        if access_token is None:
            password = self.get_password(password)

        device.entra_join(username, password, access_token, deviceticket)
        return

    def entra_delete(self, certpfx, proxy):
        device = Device(self.logger, None, None, None, None, None, None, None, proxy)
        device.entra_delete(certpfx)
        return

    def enroll_intune(
        self,
        os,
        device_name,
        username,
        password,
        refresh_token,
        tokenfile,
        certpfx,
        proxy,
        is_device,
        is_hybrid,
    ):
        if tokenfile:
            refresh_token = self.load_tokenfile(tokenfile).get("refreshToken")

        device = self.new_device(
            os, device_name, username, password, refresh_token, certpfx, proxy
        )

        if not certpfx:
            if not username or not password:
                self.logger.error("username and passwords are required")
                return
            _, refresh_token = gettokens(
                username,
                password,
                "9ba1a5c7-f17a-4de9-a1f1-6178c8d51223",
                "https://graph.microsoft.com/",
                proxy,
            )
        device.enroll_intune(certpfx, refresh_token, is_device, is_hybrid)

    def checkin(
        self,
        os,
        device_name,
        username,
        password,
        refresh_token,
        tokenfile,
        certpfx,
        mdmpfx,
        hwhash,
        proxy,
    ):
        if tokenfile:
            refresh_token = self.load_tokenfile(tokenfile).get("refreshToken")

        device = self.new_device(
            os, device_name, username, password, refresh_token, certpfx, proxy
        )
        device.hwhash = hwhash
        device.checkin(mdmpfx)
        return

    def retire_intune(
        self, os, username, password, refresh_token, tokenfile, certpfx, proxy
    ):
        if tokenfile:
            refresh_token = self.load_tokenfile(tokenfile).get("refreshToken")

        device = self.new_device(
            os, None, username, password, refresh_token, certpfx, proxy
        )
        device.retire_intune()
        return

    def check_compliant(
        self, username, password, refresh_token, tokenfile, certpfx, proxy
    ):
        if tokenfile:
            refresh_token = self.load_tokenfile(tokenfile).get("refreshToken")

        device = self.new_device(
            "Windows", None, username, password, refresh_token, certpfx, proxy
        )
        device.check_compliant()
        return

    def download_apps(self, device_name, mdmpfx, proxy):
        device = self.new_device("Windows", device_name, None, None, None, None, proxy)
        device.download_apps(mdmpfx)

    def download_remediation_scripts(self, device_name, mdmpfx, proxy):
        device = self.new_device("Windows", device_name, None, None, None, None, proxy)
        device.download_remediation_scripts(mdmpfx)


@app.command()
def entra_join(
    device_name: Annotated[
        str, typer.Option("-d", "--device-name", help="device name")
    ],
    os: Annotated[str, typer.Option("-o", "--os", help="os")],
    username: Annotated[
        Optional[str], typer.Option("-u", "--username", help="username")
    ] = None,
    password: Annotated[
        Optional[str], typer.Option("-p", "--password", help="password")
    ] = None,
    access_token: Annotated[
        Optional[str],
        typer.Option(
            "-a", "--access-token", help="access token for device registration service"
        ),
    ] = None,
    tokenfile: Annotated[
        Optional[str],
        typer.Option(
            "-f", "--tokenfile", help="token file from roadtx (ex. .roadtools_auth)"
        ),
    ] = None,
    deviceticket: Annotated[
        Optional[str], typer.Option("-D", "--deviceticket", help="device ticket")
    ] = None,
):
    """Join device to Entra ID"""
    pytune = Pytune(ctx.logger)
    pytune.entra_join(
        username,
        password,
        access_token,
        tokenfile,
        device_name,
        os,
        deviceticket,
        ctx.proxy,
    )


@app.command()
def entra_delete(
    certpfx: Annotated[
        str, typer.Option("-c", "--certpfx", help="device cert pfx path")
    ],
):
    """Delete device from Entra ID"""
    pytune = Pytune(ctx.logger)
    pytune.entra_delete(certpfx, ctx.proxy)


@app.command()
def enroll_intune(
    device_name: Annotated[
        str, typer.Option("-d", "--device-name", help="device name")
    ],
    os: Annotated[str, typer.Option("-o", "--os", help="os")],
    username: Annotated[
        Optional[str], typer.Option("-u", "--username", help="username")
    ] = None,
    password: Annotated[
        Optional[str], typer.Option("-p", "--password", help="password")
    ] = None,
    refresh_token: Annotated[
        Optional[str],
        typer.Option(
            "-r",
            "--refresh-token",
            help="refresh token for device registration service",
        ),
    ] = None,
    tokenfile: Annotated[
        Optional[str],
        typer.Option(
            "-f", "--tokenfile", help="token file from roadtx (ex. .roadtools_auth)"
        ),
    ] = None,
    certpfx: Annotated[
        Optional[str], typer.Option("-c", "--certpfx", help="device cert pfx path")
    ] = None,
    device_token: Annotated[
        bool, typer.Option("--device-token", help="use device token for enrollment")
    ] = False,
    hybrid: Annotated[
        bool, typer.Option("--hybrid", help="impersonate Entra hybrid joined device")
    ] = False,
):
    """Enroll device to Intune"""
    pytune = Pytune(ctx.logger)
    pytune.enroll_intune(
        os,
        device_name,
        username,
        password,
        refresh_token,
        tokenfile,
        certpfx,
        ctx.proxy,
        device_token,
        hybrid,
    )


@app.command()
def checkin(
    device_name: Annotated[
        str, typer.Option("-d", "--device-name", help="device name")
    ],
    os: Annotated[str, typer.Option("-o", "--os", help="os")],
    mdmpfx: Annotated[str, typer.Option("-m", "--mdmpfx", help="mdm pfx path")],
    username: Annotated[
        Optional[str], typer.Option("-u", "--username", help="username")
    ] = None,
    password: Annotated[
        Optional[str], typer.Option("-p", "--password", help="password")
    ] = None,
    refresh_token: Annotated[
        Optional[str],
        typer.Option(
            "-r",
            "--refresh-token",
            help="refresh token for device registration service",
        ),
    ] = None,
    tokenfile: Annotated[
        Optional[str],
        typer.Option(
            "-f", "--tokenfile", help="token file from roadtx (ex. .roadtools_auth)"
        ),
    ] = None,
    certpfx: Annotated[
        Optional[str], typer.Option("-c", "--certpfx", help="device cert pfx path")
    ] = None,
    hwhash: Annotated[
        Optional[str], typer.Option("-H", "--hwhash", help="Autopilot hardware hash")
    ] = None,
):
    """Checkin to Intune"""
    pytune = Pytune(ctx.logger)
    pytune.checkin(
        os,
        device_name,
        username,
        password,
        refresh_token,
        tokenfile,
        certpfx,
        mdmpfx,
        hwhash,
        ctx.proxy,
    )


@app.command()
def retire_intune(
    os: Annotated[str, typer.Option("-o", "--os", help="os")],
    certpfx: Annotated[
        str, typer.Option("-c", "--certpfx", help="device cert pfx path")
    ],
    username: Annotated[
        Optional[str], typer.Option("-u", "--username", help="username")
    ] = None,
    password: Annotated[
        Optional[str], typer.Option("-p", "--password", help="password")
    ] = None,
    refresh_token: Annotated[
        Optional[str],
        typer.Option(
            "-r",
            "--refresh-token",
            help="refresh token for device registration service",
        ),
    ] = None,
    tokenfile: Annotated[
        Optional[str],
        typer.Option(
            "-f", "--tokenfile", help="token file from roadtx (ex. .roadtools_auth)"
        ),
    ] = None,
):
    """Retire device from Intune"""
    pytune = Pytune(ctx.logger)
    pytune.retire_intune(
        os, username, password, refresh_token, tokenfile, certpfx, ctx.proxy
    )


@app.command()
def check_compliant(
    certpfx: Annotated[
        str, typer.Option("-c", "--certpfx", help="device cert pfx path")
    ],
    username: Annotated[
        Optional[str], typer.Option("-u", "--username", help="username")
    ] = None,
    password: Annotated[
        Optional[str], typer.Option("-p", "--password", help="password")
    ] = None,
    refresh_token: Annotated[
        Optional[str],
        typer.Option(
            "-r",
            "--refresh-token",
            help="refresh token for device registration service",
        ),
    ] = None,
    tokenfile: Annotated[
        Optional[str],
        typer.Option(
            "-f", "--tokenfile", help="token file from roadtx (ex. .roadtools_auth)"
        ),
    ] = None,
):
    """Check compliant status"""
    pytune = Pytune(ctx.logger)
    pytune.check_compliant(
        username, password, refresh_token, tokenfile, certpfx, ctx.proxy
    )


@app.command()
def download_apps(
    device_name: Annotated[
        str, typer.Option("-d", "--device-name", help="device name")
    ],
    mdmpfx: Annotated[str, typer.Option("-m", "--mdmpfx", help="mdm pfx path")],
):
    """Download available win32apps and scripts (only Windows supported since I'm lazy)"""
    pytune = Pytune(ctx.logger)
    pytune.download_apps(device_name, mdmpfx, ctx.proxy)


@app.command()
def get_remediations(
    device_name: Annotated[
        str, typer.Option("-d", "--device-name", help="device name")
    ],
    mdmpfx: Annotated[str, typer.Option("-m", "--mdmpfx", help="mdm pfx path")],
):
    """Download available remediation scripts (only Windows supported since I'm lazy)"""
    pytune = Pytune(ctx.logger)
    pytune.download_remediation_scripts(device_name, mdmpfx, ctx.proxy)


if __name__ == "__main__":
    app()
