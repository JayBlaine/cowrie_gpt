
breakdown_cmds = ['vim', 'emacs', 'nano', ]

# TODO: viewing log files breaking down due to openai use policy

net_cmds = ['wget', 'curl', 'ping']

alt_context_cmds = ['history', ]

installed_pkgs = []

system_injection_cmds = ['install', 'dpkg']

context_cmds = ['cd', 'touch', 'chmod', 'chown', 'chgrp', '>', 'install', 'dpkg', 'chage', 'dd', 'zip', 'tar', '7z', 'ip addr'
                'objcopy', 'nohup', 'mount', 'adduser', 'addgroup', 'useradd', 'userdel', 'passwd', 'mkdir', 'rm', 'grub-install',
                'fsck', 'kill', 'mk', 'update', 'iptables', 'wget', 'netstat']

sanitize_triggers = ['note', 'ai', 'language model', 'large language model', 'unable', 'unethical']

# virt

kill_cmds = ['reboot', 'shutdown', 'exit', 'logout']
