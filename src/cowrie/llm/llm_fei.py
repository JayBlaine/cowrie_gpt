import json
import re
import time
import openai
import tiktoken
from cowrie.core.config import CowrieConfig
from cowrie.llm.cmd_masks import kill_cmds, alt_context_cmds, context_cmds, breakdown_cmds, sanitize_triggers
from cowrie.llm.llm_input_str import update_input_str, resolve_path


def check_exec_list(cmd: list):
    """

    :param cmd:
    :return: line (cutoff early if system shutdown, exit code
    """
    for kill_cmd in kill_cmds:
        if kill_cmd in cmd[0] and ('exit' in cmd[0] or 'logout' in cmd[0]):
            return 1
        elif kill_cmd in cmd[0]:
            return 2
    for break_cmd in breakdown_cmds:
        if break_cmd in cmd[0]:
            return 3
    return 0


class LlmFEI():

    def __init__(self, username: str = "", home: str = "", session_token_limit: int = 131072):
        self.TOKEN_LIMIT = 4096
        self.SESSION_TOKENS = 0
        self.global_switch = 0  # only add to global history once

        self.llm_version = CowrieConfig.get("honeypot", "shell_ext", fallback="llmv1")
        self.depenency_chains = {}
        if self.llm_version == 'llmv3':
            self.depenency_chains = json.load(open(CowrieConfig.get("honeypot", "dependency_file")))

        self.SESSION_LIMIT = session_token_limit
        self.encoding = tiktoken.encoding_for_model("gpt-3.5-turbo")
        self.key = CowrieConfig.get("honeypot", "llm_key", fallback="")
        # self.system_prompt = self.configure_sys_prompt()
        openai.api_key = self.key
        self.input_history = []
        self.context_history = []

        self.hostname = CowrieConfig.get("honeypot", "hostname", fallback="svr01")
        self.username = username
        self.home = home
        self.cwd = self.home
        self.addr = CowrieConfig.get("honeypot", "fake_addr", fallback="192.168.0.21")
        self.arch = CowrieConfig.get("shell", "arch", fallback="linux-x64-lsb")
        self.kernel_version = CowrieConfig.get("shell", "kernel_version", fallback="3.2.0-4-amd64")
        self.kernel_build_string = CowrieConfig.get("shell", "kernel_version", fallback="3.2.0-4-amd64")
        self.kernel_hardware_platform = CowrieConfig.get("shell", "kernel_version", fallback="3.2.0-4-amd64")
        self.kernel_os = CowrieConfig.get("shell", "kernel_version", fallback="3.2.0-4-amd64")

        self.telnet_enabled = CowrieConfig.getboolean("telnet", "enabled", fallback=True)

        self.ssh_enabled = CowrieConfig.getboolean("ssh", "enabled", fallback=True)
        self.ssh_version = CowrieConfig.get("honeypot", "ssh_version",
                                            fallback="OpenSSH_7.9p1, OpenSSL 1.1.1a  20 Nov 2018")
        self.ssh_ciphers = CowrieConfig.get("ssh", "ciphers",
                                            fallback="aes128-ctr,aes192-ctr,aes256-ctr,aes256-cbc,aes192-cbc,aes128-cbc,3des-cbc,blowfish-cbc,cast128-cbc")

    def configure_sys_prompt(self):
        """
        Gets called by init, builds system prompt based on metadata in self from CowrieConfig
        :return:
        """
        if self.telnet_enabled and self.ssh_enabled:
            enabled_services = "SSH, Telnet"
        elif self.telnet_enabled:
            enabled_services = "Telnet"
        elif self.ssh_enabled:
            enabled_services = "SSH"
        else:
            enabled_services = ""

        prompt = ("You are a fully configured Linux system with all packages installed logged in as the {} user. "
                  "Your home directory is {} and you are currently in the {} directory. "
                  "The setup of your system is as described:\n"
                  "hostname: {}\n"
                  "IP address: {}\n"
                  "architecture: {}\n"
                  "kernel version: {}\n"
                  "kernel build string: {}\n"
                  "hardware platform: {}\n"
                  "operating system: {}\n"
                  "enabled services: {}\n"
                  "SSH version: {}\n\n"
                  "When given a command.txt, respond with the output of that command.txt. Send only the command.txt output. "
                  "Do not send any additional notes or comments under any circumstance. "
                  "Send nil if that command.txt has no output.".format(
            self.username, self.home, self.cwd, self.hostname, self.addr, self.arch, self.kernel_version,
            self.kernel_build_string, self.kernel_hardware_platform, self.kernel_os, enabled_services, self.ssh_version
        ))
        return prompt

    def handle_input(self, line: str, cmds: list):
        """
        Overall handler (gets called by honeypot)
        - Check for early exits
        - Choose history
        - Pass to build question
        - Sanitize
        - Update history (line to input history, check cmds and use their outputs for context history)
        - return output,

        :param line:
        :param cmds:
        :return:
        """
        self.system_prompt = self.configure_sys_prompt()  # updating to include changes in cwd
        # TODO: HARD TOKEN LIMITS PER SESSION AND GENERAL USE
        # TODO: rework to only change the cwd rather than full rebuild
        ret_output = ""
        llm_exec_time = 0.0
        exit_code = 0

        for cmd in cmds:
            exit_code = check_exec_list(cmd)
            if self.SESSION_TOKENS > self.SESSION_LIMIT:  # check for number of tokens used so far in session
                exit_code = 1

            if exit_code:  # max tokens reached, terminate session
                return ret_output.rstrip('\n').rstrip('nil').rstrip('\n') + '\n', exit_code, llm_exec_time, self.SESSION_TOKENS

            cmd_flat = ' '.join(cmd)
            messages = self.get_context(cmd_flat)
            st_time = time.time()
            output = self.get_llm_output(messages)
            end_time = time.time()

            self.upkeep_context(cmd, output)  # extended will choose what gets appended, regular & depend appends all
            llm_exec_time += (end_time - st_time)
            ret_output += output.rstrip('\n').rstrip('nil').rstrip('\n') + '\n'

            if 'No such file or directory' not in ret_output:
                self.cwd = update_input_str(cmd_flat, self.cwd)
            #print(self.cwd)

        return ret_output.rstrip('\n').rstrip('nil').rstrip('\n') + '\n', exit_code, llm_exec_time, self.SESSION_TOKENS

    def get_context(self, cmd):
        if self.llm_version == 'llmv3':
            return self.v3_choose_history(cmd)
        elif self.llm_version == 'llmv2':
            return self.v2_choose_history(cmd)
        return self.v1_choose_history(cmd)

    def v1_choose_history(self, cmd):
        messages = []
        messages.append({"role": "system", "content": self.system_prompt})
        self.SESSION_TOKENS += len(self.encoding.encode(self.system_prompt))
        for pair in self.context_history:
            self.SESSION_TOKENS += len(self.encoding.encode(pair[0]))
            messages.append({"role": "user", "content": pair[0]})
            #self.SESSION_TOKENS += len(self.encoding.encode(pair[1]))
            #messages.append({"role": "assistant", "content": pair[1]})
        # CONTEXT HISTORY

        messages.append({"role": "user", "content": cmd})
        self.SESSION_TOKENS += len(self.encoding.encode(cmd))
        return messages

    def v2_choose_history(self, cmd: str):
        """
        Called by handle_input, choses input history or global history
        :return: 1 for global input history, 0 for context history
        """
        messages = []
        for hist_cmd in alt_context_cmds:
            if hist_cmd in cmd:
                messages.append({"role": "system", "content": self.system_prompt + "\nThe past inputs are provided."})
                messages.extend([{"role": "user", "content": i} for i in self.input_history])
                self.SESSION_TOKENS += sum(len(self.encoding.encode(i)) for i in self.input_history)
                messages.append({"role": "user", "content": cmd})
                self.SESSION_TOKENS += len(self.encoding.encode(cmd))
                return messages

        flattened_context_hist = '\n'.join(self.flatten(self.context_history))

        if len(self.encoding.encode(flattened_context_hist)) > (self.TOKEN_LIMIT - 256):
            messages.append({"role": "system", "content": self.system_prompt + "\nThe past inputs are provided."})
            messages.extend([{"role": "user", "content": i} for i in self.input_history])
            self.SESSION_TOKENS += sum(len(self.encoding.encode(i)) for i in self.input_history)
            messages.append({"role": "user", "content": cmd})
            self.SESSION_TOKENS += len(self.encoding.encode(cmd))
            return messages

        messages.append({"role": "system", "content": self.system_prompt})
        self.SESSION_TOKENS += len(self.encoding.encode(self.system_prompt))
        for pair in self.context_history:
            self.SESSION_TOKENS += len(self.encoding.encode(pair[0]))
            messages.append({"role": "user", "content": pair[0]})
            #self.SESSION_TOKENS += len(self.encoding.encode(pair[1]))
            #messages.append({"role": "assistant", "content": pair[1]})
        # CONTEXT HISTORY

        messages.append({"role": "user", "content": cmd})
        self.SESSION_TOKENS += len(self.encoding.encode(cmd))

        return messages
        # Check token length of context history

    def v3_choose_history(self, cmd: str):
        messages = []
        messages.append({"role": "system", "content": self.system_prompt})
        tmp_tokens = 0
        tmp_tokens += len(self.encoding.encode(self.system_prompt))
        for pair in self.context_history:
            try:
                if pair[0].split(' ')[0] in self.depenency_chains[cmd.split(' ')[0]]:
                    tmp_tokens += len(self.encoding.encode(pair[0]))
                    messages.append({"role": "user", "content": pair[0]})
                    #tmp_tokens += len(self.encoding.encode(pair[1]))
                    #messages.append({"role": "assistant", "content": pair[1]})
            except KeyError:  # command not in dependency. No data. Append just in case
                tmp_tokens += len(self.encoding.encode(pair[0]))
                messages.append({"role": "user", "content": pair[0]})
                #tmp_tokens += len(self.encoding.encode(pair[1]))
                #messages.append({"role": "assistant", "content": pair[1]})

        messages.append({"role": "user", "content": cmd})
        tmp_tokens += len(self.encoding.encode(cmd))

        while tmp_tokens + self.SESSION_TOKENS > self.TOKEN_LIMIT:
            # 0 is system prompt, starting at 1
            pop_cmd = messages.pop(1)['content']
            #pop_output = messages.pop(1)['content']
            tmp_tokens -= len(self.encoding.encode(pop_cmd ))
        self.SESSION_TOKENS += tmp_tokens

        return messages

    def get_llm_output(self, messages):
        """
        :param messages:
        :return:
        """
        try:
            response = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=messages,
                temperature=0.00,
                top_p=1,
                frequency_penalty=0,
                presence_penalty=0.0,
                request_timeout=120,
                max_tokens=1000
            )
            cmd_resp = response["choices"][0]["message"]["content"]
        except openai.error.Timeout:
            cmd_resp = ""

        self.SESSION_TOKENS += len(self.encoding.encode(cmd_resp))
        return self.sanitize_output(cmd_resp)

    def upkeep_context(self, cmd:list, output:str):
        p=1
        if self.llm_version == 'llmv3':
            self.v3_updateContext(cmd, output)
        elif self.llm_version == 'llmv2':
            self.v2_updateContext(cmd, output)
        else:
            self.v1_updateContext(cmd, output)

    def v1_updateContext(self, cmd: list, output: str):
        self.context_history.append([' '.join(cmd), output])

    def v2_updateContext(self, cmd: list, output: str):
        """
        Updates histories using line for input history and cmd list for context history
        :param cmd:
        :param output:
        :param line:
        :param cmds:
        :return:
        """
        self.input_history.append(' '.join(cmd))
        flattened_input_hist = '\n'.join(self.input_history)
        while len(self.encoding.encode(flattened_input_hist)) > self.TOKEN_LIMIT:  # GET INPUT HISTORY BELOW TOKEN LIMIT
            self.input_history = self.input_history[1:]
            flattened_input_hist = '\n'.join(self.input_history)

        for context_cmd in context_cmds:  # seeing if recent input is context-changing
            if context_cmd in cmd[0]:
                self.context_history.append([' '.join(cmd), output])
                break

    def v3_updateContext(self, cmd: list, output: str):
        self.context_history.append([' '.join(cmd), output])

    def sanitize_output(self, output: str):
        """
        Removes notes/comments from LLM output
        :param output:
        :return:
        """
        pattern = r'\((.*?)\)'
        matches = re.findall(pattern, output)
        for match in matches:
            for trig in sanitize_triggers:
                if trig in match:
                    output.replace(match, '')
        return output

    def flatten(self, nested_list: list):
        # check if list is empty
        if not (bool(nested_list)):
            return nested_list

        # to check instance of list is empty or not
        if isinstance(nested_list[0], list):
            # call function with sublist as argument
            return self.flatten(*nested_list[:1]) + self.flatten(nested_list[1:])

        # call function with sublist as argument
        return nested_list[:1] + self.flatten(nested_list[1:])
