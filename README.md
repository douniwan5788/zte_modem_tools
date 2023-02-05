# ENV

```
python3 -m venv .venv
source ./.venv/bin/activate
pip install -r requirements.txt
```

# zte_factroymode.py

open telnet(use embed user/pass to 192.168.1.1 80):

`python3 zte_factroymode.py telnet`

or custom args

`python3 zte_factroymode.py --user CUAdmin --pass CUAdmin --ip 192.168.1.1 --port 80 telnet open`

```shell
$ python3 ./zte_factroymode.py -h
usage: zte_factroymode [-h] [--user USER [USER ...]] [--pass PASS [PASS ...]] [--ip IP] [--port PORT] {telnet,serial} ...

options:
  -h, --help            show this help message and exit
  --user USER [USER ...], -u USER [USER ...]
                        factorymode auth username (default: ['factorymode', 'CMCCAdmin', 'CUAdmin', 'telecomadmin', 'cqadmin', 'user', 'admin', 'cuadmin', 'lnadmin', 'useradmin'])
  --pass PASS [PASS ...], -p PASS [PASS ...]
                        factorymode auth password (default: ['nE%jA@5b', 'aDm8H%MdA', 'CUAdmin', 'nE7jA%5m', 'cqunicom', '1620@CTCC', '1620@CUcc', 'admintelecom', 'cuadmin', 'lnadmin'])
  --ip IP               route ip (default: 192.168.1.1)
  --port PORT           router http port (default: 80)

subcommands:
  valid subcommands

  {telnet,serial}       supported commands
    telnet              control telnet services on/off
    serial              control /proc/serial on/off

https://github.com/douniwan5788/zte_modem_tools
```

# zte_hardcode_dump.py

decrypt /etc/hardcodefile

`./zte_hardcode_dump.py test/hardcode test/hardcodefile/*`

```shell
$ python3 ./zte_hardcode_dump.py -h
usage: zte_hardcode_dump [-h] hardcode hardcodefile [hardcodefile ...]

positional arguments:
  hardcode      the /etc/hardcode file which contains root key
  hardcodefile  config files under /etc/hardcodefile

options:
  -h, --help    show this help message and exit

https://github.com/douniwan5788/zte_modem_tools
```
