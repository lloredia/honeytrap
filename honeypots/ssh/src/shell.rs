//! Fake Shell Implementation

use std::collections::HashMap;

pub struct FakeShell {
    cwd: String,
    env: HashMap<String, String>,
    hostname: String,
}

impl Default for FakeShell {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeShell {
    pub fn new() -> Self {
        let mut env = HashMap::new();
        env.insert(
            "PATH".to_string(),
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
        );
        env.insert("HOME".to_string(), "/root".to_string());
        env.insert("USER".to_string(), "root".to_string());

        Self {
            cwd: "/root".to_string(),
            env,
            hostname: "server".to_string(),
        }
    }

    pub fn get_prompt(&self, username: &str) -> String {
        let symbol = if username == "root" { "#" } else { "$" };
        format!("{}@{}:{}{} ", username, self.hostname, self.cwd, symbol)
    }

    pub fn cwd(&self) -> &str {
        &self.cwd
    }

    pub fn execute(&mut self, command: &str) -> String {
        let command = command.trim();
        if command.is_empty() {
            return String::new();
        }

        let parts: Vec<&str> = command.split_whitespace().collect();
        let cmd = parts.first().unwrap_or(&"");
        let args: Vec<&str> = parts.iter().skip(1).cloned().collect();

        match *cmd {
            "ls" => self.cmd_ls(&args),
            "pwd" => self.cwd.clone(),
            "cd" => self.cmd_cd(&args),
            "cat" => self.cmd_cat(&args),
            "whoami" => self
                .env
                .get("USER")
                .cloned()
                .unwrap_or_else(|| "root".to_string()),
            "id" => "uid=0(root) gid=0(root) groups=0(root)".to_string(),
            "uname" => self.cmd_uname(&args),
            "hostname" => self.hostname.clone(),
            "echo" => args.join(" "),
            "env" | "printenv" => self
                .env
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join("\r\n"),
            "ps" => FAKE_PS.to_string(),
            "netstat" => FAKE_NETSTAT.to_string(),
            "ifconfig" | "ip" => FAKE_IFCONFIG.to_string(),
            "wget" => format!(
                "wget: unable to resolve host address '{}'",
                args.last().unwrap_or(&"unknown")
            ),
            "curl" => format!(
                "curl: (6) Could not resolve host: {}",
                args.last().unwrap_or(&"unknown")
            ),
            "chmod" | "mkdir" | "rm" | "touch" | "cp" | "mv" => String::new(),
            "w" | "who" => "root     pts/0    Jan 20 10:30 (192.168.1.100)".to_string(),
            "uptime" => " 10:30:45 up 15 days, 1 user, load average: 0.00, 0.01, 0.05".to_string(),
            "free" => FAKE_FREE.to_string(),
            "df" => FAKE_DF.to_string(),
            "date" => chrono::Utc::now()
                .format("%a %b %d %H:%M:%S UTC %Y")
                .to_string(),
            "exit" | "logout" => "logout".to_string(),
            "clear" => "\x1b[2J\x1b[H".to_string(),
            _ => format!("bash: {}: command not found", cmd),
        }
    }

    fn cmd_ls(&self, args: &[&str]) -> String {
        let long = args.contains(&"-l") || args.contains(&"-la") || args.contains(&"-al");
        let all = args.contains(&"-a") || args.contains(&"-la") || args.contains(&"-al");

        if self.cwd == "/root" {
            if long {
                let mut out = String::new();
                if all {
                    out.push_str("drwx------  4 root root 4096 Jan 15 10:30 .\r\n");
                    out.push_str("drwxr-xr-x 18 root root 4096 Jan 15 10:30 ..\r\n");
                    out.push_str("-rw-------  1 root root  123 Jan 15 10:30 .bash_history\r\n");
                    out.push_str("-rw-r--r--  1 root root 3106 Jan 15 10:30 .bashrc\r\n");
                }
                out.push_str("-rw-r--r--  1 root root  161 Jan 15 10:30 .profile\r\n");
                out.push_str("drwx------  2 root root 4096 Jan 15 10:30 .ssh");
                out
            } else if all {
                ".  ..  .bash_history  .bashrc  .profile  .ssh".to_string()
            } else {
                ".profile  .ssh".to_string()
            }
        } else if self.cwd == "/" {
            if long {
                "drwxr-xr-x   2 root root  4096 Jan 15 10:30 bin\r\n\
                 drwxr-xr-x   2 root root  4096 Jan 15 10:30 boot\r\n\
                 drwxr-xr-x   5 root root   360 Jan 20 10:30 dev\r\n\
                 drwxr-xr-x  80 root root  4096 Jan 15 10:30 etc\r\n\
                 drwxr-xr-x   3 root root  4096 Jan 15 10:30 home\r\n\
                 drwxr-xr-x   2 root root  4096 Jan 15 10:30 lib\r\n\
                 drwxr-xr-x   2 root root  4096 Jan 15 10:30 lib64\r\n\
                 drwxr-xr-x   2 root root  4096 Jan 15 10:30 opt\r\n\
                 dr-xr-xr-x 200 root root     0 Jan 20 10:30 proc\r\n\
                 drwx------   4 root root  4096 Jan 15 10:30 root\r\n\
                 drwxr-xr-x   2 root root  4096 Jan 15 10:30 sbin\r\n\
                 drwxr-xr-x   2 root root  4096 Jan 15 10:30 srv\r\n\
                 dr-xr-xr-x  13 root root     0 Jan 20 10:30 sys\r\n\
                 drwxrwxrwt   2 root root  4096 Jan 20 10:30 tmp\r\n\
                 drwxr-xr-x  10 root root  4096 Jan 15 10:30 usr\r\n\
                 drwxr-xr-x  11 root root  4096 Jan 15 10:30 var"
                    .to_string()
            } else {
                "bin  boot  dev  etc  home  lib  lib64  opt  proc  root  sbin  srv  sys  tmp  usr  var".to_string()
            }
        } else if self.cwd == "/etc" {
            "hostname  hosts  passwd  shadow  ssh".to_string()
        } else {
            String::new()
        }
    }

    fn cmd_cd(&mut self, args: &[&str]) -> String {
        let target = args.first().unwrap_or(&"~");
        let new_cwd = match *target {
            "~" | "" => "/root".to_string(),
            "/" => "/".to_string(),
            ".." => {
                if self.cwd == "/" {
                    "/".to_string()
                } else {
                    let parts: Vec<_> = self.cwd.split('/').filter(|s| !s.is_empty()).collect();
                    if parts.len() <= 1 {
                        "/".to_string()
                    } else {
                        format!("/{}", parts[..parts.len() - 1].join("/"))
                    }
                }
            }
            path if path.starts_with('/') => path.to_string(),
            path => format!("{}/{}", self.cwd, path),
        };

        let valid = matches!(
            new_cwd.as_str(),
            "/" | "/root" | "/etc" | "/tmp" | "/home" | "/var" | "/var/log"
        );
        if valid {
            self.cwd = new_cwd;
            String::new()
        } else {
            format!("bash: cd: {}: No such file or directory", target)
        }
    }

    fn cmd_cat(&self, args: &[&str]) -> String {
        if args.is_empty() {
            return String::new();
        }

        match args[0] {
            "/etc/passwd" => FAKE_PASSWD.to_string(),
            "/etc/shadow" => "root:$6$xyz:19000:0:99999:7:::".to_string(),
            "/etc/hostname" => format!("{}\n", self.hostname),
            "/etc/hosts" => "127.0.0.1\tlocalhost\n127.0.1.1\tserver".to_string(),
            _ => format!("cat: {}: No such file or directory", args[0]),
        }
    }

    fn cmd_uname(&self, args: &[&str]) -> String {
        if args.contains(&"-a") {
            "Linux server 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux".to_string()
        } else if args.contains(&"-r") {
            "5.15.0-91-generic".to_string()
        } else {
            "Linux".to_string()
        }
    }
}

const FAKE_PASSWD: &str = "root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
admin:x:1000:1000:Admin:/home/admin:/bin/bash";

const FAKE_PS: &str = "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.1 169432 11840 ?        Ss   Jan15   0:03 /sbin/init
root       456  0.0  0.1  72296  6144 ?        Ss   Jan15   0:00 /usr/sbin/sshd
root       789  0.0  0.1  92832  8456 ?        Ss   10:30   0:00 sshd: root@pts/0
root       812  0.0  0.0   8212  5120 pts/0    Ss   10:30   0:00 -bash";

const FAKE_NETSTAT: &str = "Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN
tcp        0    216 10.0.0.5:22             192.168.1.100:54321     ESTABLISHED";

const FAKE_IFCONFIG: &str = "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.0.0.5  netmask 255.255.255.0  broadcast 10.0.0.255
        ether 02:42:0a:00:00:05  txqueuelen 0  (Ethernet)

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0";

const FAKE_FREE: &str =
    "              total        used        free      shared  buff/cache   available
Mem:        8127168     1234567     4567890      123456     2345678     6543210
Swap:       2097148           0     2097148";

const FAKE_DF: &str = "Filesystem     1K-blocks    Used Available Use% Mounted on
/dev/sda1       41284928 5678901  33487432  15% /
tmpfs            4063584       0   4063584   0% /dev/shm";
