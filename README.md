# sshpassrig

sshpassrig is a utility, inspired by Unix sshpass, that allows for passing password to a an ssh interactive
session (or other software such as scp) in an automated fashion. The tool is originally based on the sshpass-win32 project
from xhcoding.

sshpassrig is tailored to a Windows setup with an interactive user that can provide the ssh password during the first time
usage against a certain ssh user/host/port combination. The password is fed into the ssh prompt, and if login is successful,
the password shall be saved to Windows Credential Manager.

Notable features:

-   The password, if not existing in the Windows Credential Manager, shall be asked in Windows GUI from the user.
-   Hosts the ssh subprocess with a pseudo console (pty). Note that the pty is a new feature of Windows 10 October 2018
Update (version 1809), **and therefore** this utility doesn't work with earlier Windows versions.
-   Passes password to the subprocess stdin when a specific sequence of chars (e.g. "password:") is seen in one chunk of
stdout received from it. Note that the specific password prompt is a feature of the remote SSH server, and might differ
between SSH server variants.
-   Checks that the password was okay, by comparing forthcoming response against certain words, such as "denied". Correct
password will be stored in the Credential Manager
-   It can optionally strip away ANSI control escape sequences (ESC CSI) from the stdout of the subprocess. This is used
in case the output from ssh has text and caret formatting embedded in it, which is useless in case the ssh output is going
to be parsed in some external software.
    -   Note: This happens in a very simplistic way. It only strips CSI sequences (ignores other escape sequences), and it
    has limited support for emulating sequences that move the caret forward/to next line. The ssh output might in some cases
    become distorted!
-   Moreover, exception and error handling and proper initialization / clean-up has been in focused for this tool.

## Command line arguments (as of 24-09-26)

Usage: `sshpassrig [-t|-l|-T TIME_S] [-e] [-n TARGET_NAME] -- SUBCMD`

Where:

- -t: Give max 10s for execution of the SUBCMD
- -T: Give max TIME_S seconds for execution of the SUBCMD
- -l: Interactive loop: If the subprocess dies with error, start it again. This can be for instance be used to restart the
   ssh interactive shell until the user executes a successful command and then issues `$ exit`.
- -e: Suppress ANSI CSI ESC sequences from output/to input of SUBCMD. See above for details. Use this if output (stdout)
   is to be parsed or printed raw by the caller process. This also disables the input escape sequences to the subprocess,
   for example move-caret operations that are result of pressing arrow keys on keyboard.
- -n: The TARGET_NAME of SSH, formatted as `user@host[:port]`. This name is passed to SUBCMD (see below) and also used to
   look up the password in Credential Manager.
- -I: Don't print informative text
- SUBCMD: Command line to SSH/SCP, following tokens can be expanded in the command line:
    - `$FLAGS$`        -o StrictHostKeyChecking=no
    - `$PORT$`         port
    - `$TARGET$`       user@host
    - `$SSHPARAMS$`    -o StrictHostKeyChecking=no -p port user@host
    - Note that the caller need to correctly escape the `$` sign. If called in sh for example, `$` must be prepended with `\`.

## Example usage

`$ sshpassrig -l -n root@192.168.1.20:2222 -- ssh \$SSHPARAMS\$`: Invoke interactive ssh. If ssh dies with error, start
it again.

`$ sshpassrig -e -I -n root@192.168.25.44 -- ssh \$SSHPARAMS\$ apt install pckg`: SSH into the remote, run apt install pckg.
The output will not have any escape sequences, thus useful for parsing or saving in a file.

`$ sshpassrig -e -I -n -T 300 root@192.168.25.44:2222 -- scp -o ConnectTimeout=5 -q \$FLAGS\$ -P \$PORT\$ ./myfile \$TARGET\$:/var/location`:
Use scp to copy file `myfile` into `/var/location` of the target. Give maximum 5 minutes for the subprocess to finish.
Strip away CSI escape sequences.
