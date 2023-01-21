# zte_factroymode.py

open telnet(use embed user/pass to 192.168.1.1 80):

`python3 zte_factroymode.py telnet`

or custom args

`python3 zte_factroymode.py --user CUAdmin --pw CUAdmin -- 192.168.1.1 80 telnet open`

```shell
$ python3 zte_factroymode.py -h
usage: https://github.com/douniwan5788/zte_modem_tools

positional arguments:
  ip                    route ip (default: 192.168.1.1)
  port                  router http port (default: 80)

options:
  -h, --help            show this help message and exit
  --user USER [USER ...], -u USER [USER ...]
                        factorymode auth username (default: ['factorymode', 'CMCCAdmin', 'CUAdmin', 'telecomadmin', 'cqadmin', 'user',
                        'admin', 'cuadmin', 'lnadmin', 'useradmin'])
  --pass PW [PW ...], -p PW [PW ...]
                        factorymode auth password (default: ['nE%jA@5b', 'aDm8H%MdA', 'CUAdmin', 'nE7jA%5m', 'cqunicom', '1620@CTCC',
                        '1620@CUcc', 'admintelecom', 'cuadmin', 'lnadmin'])

subcommands:
  valid subcommands

  {telnet,serial}       supported commands
    telnet              control telnet services on/off
    serial              control /proc/serial on/off
```

# zte_hardcode_dump.py

decrypt /etc/hardcodefile
`./zte_hardcode_dump.py test/hardcode test/hardcodefile/*`

```shell
$ ./zte_hardcode_dump.py -h
usage: https://github.com/douniwan5788/zte_modem_tools

positional arguments:
  hardcode      the /etc/hardcode file which contains root key
  hardcodefile  config files under /etc/hardcodefile

options:
  -h, --help    show this help message and exit
```
