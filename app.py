## DEPENDENCIES ##
from flask import Flask, render_template, request, jsonify, session # external
import docker, ansible_runner, paramiko # external
import os, atexit, signal, time,json, logging, tempfile # built-in


## GLOBAL CONFIGURATION ##
app = Flask(__name__) # create a Flask app
app.secret_key = os.urandom(24)  # set a secret key for session management

client = docker.from_env() # connect to docker daemon

logging.basicConfig(level=logging.DEBUG) # gives us access to 'app.logger'

## SSH KEY SETUP ##
ssh_key_dir = os.path.expanduser("~/.ssh")
ssh_key_path = os.path.join(ssh_key_dir, "docker_container_key")
public_key_path = ssh_key_path + ".pub"

## CLEANUP ON EXIT SETUP ##
def cleanup_on_exit():
    """calls the cleanup route at app shutdown to remove any spawned containers."""
    with app.test_client() as flask_client:
        response = flask_client.post('/remove_all_containers') # calls remove_all_containers route
        app.logger.info(f"Cleanup result: {response.get_data(as_text=True)}")

atexit.register(cleanup_on_exit) # register 'cleanup' to run when the app quits or receives SIGINT

def handle_sigint(signum, frame):
    """Custom signal handler to catch Ctrl+C (SIGINT) interrupts."""
    app.logger.info("Received SIGINT (Ctrl+C), cleaning up...")
    cleanup_on_exit()  # run the cleanup before exiting
    exit(0)

signal.signal(signal.SIGINT, handle_sigint) # register the SIGINT handler


## HELPER FUNCTIONS ##
def ensure_ssh_key():
    """
    Ensures the presence of an SSH key pair for secure container access.
    If the key doesn't exist, it is generated automatically.
    """
    os.makedirs(ssh_key_dir, exist_ok=True) # ensure .ssh directory exists

    if not os.path.exists(ssh_key_path) or not os.path.exists(public_key_path):
        app.logger.info("Generating new SSH key pair...")
        cmd = f"ssh-keygen -t rsa -b 4096 -f {ssh_key_path} -N ''"

        if os.system(cmd) != 0:
            raise RuntimeError("SSH key pair generation failed.")
        
        os.chmod(ssh_key_path, 0o600)  # ensure private key is secure

    with open(public_key_path, "r") as key_file:
        return key_file.read().strip()

def spawn_container(public_key):
    try:
        container = client.containers.run(
            'debian:bullseye-slim',
            command=f'/bin/bash -c "\
                    apt-get update && \
                    apt-get install -y openssh-server python3 && \
                    mkdir -p /run/sshd && \
                    mkdir -p /root/.ssh && \
                    echo \'{public_key}\' > /root/.ssh/authorized_keys && \
                    chmod 600 /root/.ssh/authorized_keys && \
                    chmod 700 /root/.ssh && \
                    sed -i \'s/#PermitRootLogin prohibit-password/PermitRootLogin yes/\' /etc/ssh/sshd_config && \
                    sed -i \'s/#PubkeyAuthentication yes/PubkeyAuthentication yes/\' /etc/ssh/sshd_config && \
                    sed -i \'s@#PasswordAuthentication yes@PasswordAuthentication no@\' /etc/ssh/sshd_config && \
                    /usr/sbin/sshd && \
                    tail -f /dev/null"',
            detach = True,
            ports = {'22/tcp': None},  # let docker assign a random port
            tty = True,
            labels = {"flask_app": "spawned_container"} # custom label for faster lookup (docker inspect)
        )

        app.logger.info(f"Container {container.id} spawned successfully")
        return container

    except Exception as e:
        app.logger.error(f"Error spawning container: {str(e)}")
        raise

def wait_for_ssh(host, port, retries=5, delay=5):
    """
    Waits for SSH to be available on the specified host and port, with exponential backoff.
    """
    for attempt in range(retries):
        try:
            with paramiko.SSHClient() as client:
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(hostname=host, port=port, username='root', key_filename=ssh_key_path, timeout=5)

            app.logger.info(f"SSH is ready on {host}:{port}.")
            return True

        except Exception as e:
            app.logger.debug(f"SSH attempt {attempt + 1}/{retries} failed: {e}")
            time.sleep(delay * (2 ** attempt))  # exponential backoff

    app.logger.error(f"SSH not ready after {retries} attempts.")
    return False

def wait_for_container(container, timeout=60, interval=5):
    """
    Waits for a container to initialize and report its SSH readiness.
    """
    elapsed = 0
    while elapsed < timeout:
        container.reload()
        ports = container.attrs['NetworkSettings']['Ports']

        if ports and ports.get('22/tcp') and ports['22/tcp'][0]['HostPort']:
            host_port = ports['22/tcp'][0]['HostPort']

            if wait_for_ssh('localhost', host_port):
                return host_port

        app.logger.info(f"Waiting for container {container.id[:12]} to initialize...")
        time.sleep(interval)
        elapsed += interval

    raise TimeoutError(f"Container {container.id[:12]} failed to initialize within {timeout} seconds.")

def create_temp_file(content, suffix, writer=lambda content, file: file.write(content)):
    """
    Creates a secure temporary file with the specified content and suffix.
    """
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=suffix) as temp_file:
        os.chmod(temp_file.name, 0o600) # secure file
        writer(content, temp_file) # write file contents (using provided function)
        return temp_file.name

def parse_ansible_results(result):
    """
    Parses Ansible results from a given AnsibleRunner object.
    """
    results = {}

    for host_event in result.events:
        if host_event['event'] == 'runner_on_ok':
            event_data = host_event.get('event_data', {}) # host_event['event_data']
            event_result = event_data.get('res', {})      # event_data['res']

            if 'stdout' in event_result:
                results[event_data['host']] = event_result['stdout']

    return results 

def cleanup_files(file_paths):
    """
    Removes temporary files created during the application lifecycle.
    """
    for file_path in file_paths:
        if os.path.exists(file_path):
            os.unlink(file_path)

def run_ansible(hosts, command):
    """
    Runs an Ansible playbook on specified hosts with a given command.
    """
    try:
        inventory = {
            "all": {
                "hosts": hosts
            }
        }
        inventory_file_path = create_temp_file(
            content = inventory,
            suffix = '.json',
            writer = json.dump
        )

        playbook_content = f'''
        - name: Run custom command on all hosts
          hosts: all
          tasks:
            - name: Execute custom command
              command: {command}
              register: command_output
            - debug:
                var: command_output.stdout
        '''
        playbook_file_path = create_temp_file(
            content = playbook_content,
            suffix = '.yml'
        )

        app.logger.info(f"Running Ansible playbook on hosts: {hosts}")
        result = ansible_runner.run(
            private_data_dir='/tmp',
            playbook=playbook_file_path,
            inventory=inventory_file_path,
            extravars={'ansible_ssh_private_key_file': ssh_key_path}
        )

        return parse_ansible_results(result)

    except Exception as e:
        app.logger.error(f"Error running Ansible: {str(e)}")
        raise

    finally:
        cleanup_files([inventory_file_path, playbook_file_path])

def remove_or_stop_containers(containers, action):
    """
    Stops or removes the specified containers based on the action parameter.
    """
    for container in containers:
        try:
            if container.status == 'running':
                container.stop() # [NOTE] default timeout is culprit for unssuccessful removal in 1st attempt
            if action == 'remove':
                container.remove()
            app.logger.info(f"spawned container {container.id[:12]} {'removed' if action == 'remove' else 'stopped'}")

        except Exception as e:
            app.logger.warning(f"Failed to {action} spawned container {container.id[:12]}: {str(e)}")


## ROUTES FOR FLASK APP ##
# HTTP status codes: 200 - OK (default), 400 - Bad Request, 404 - Not Found, 500 - Internal Server Error

@app.route('/')
def MAIN_INDEX_ROUTE():
    return render_template('index.html')

@app.route('/spawn', methods=['POST'])
def SPAWN_MACHINES_ROUTE():
    try:
        num_machines = request.form.get('num_machines', type=int)
        if not isinstance(num_machines, int) or num_machines <= 0:
            return jsonify({"error": "Invalid 'num_machines' value. Must be a positive integer."}), 400

        public_key = ensure_ssh_key()
        containers = []  # Track spawned containers
        machine_info = []  # Track machine details for display

        for _ in range(num_machines):
            try:
                container = spawn_container(public_key)                
                host_port = wait_for_container(container)
                containers.append(container)
                machine_info.append({
                    'container_id': container.id[:12],
                    'host_port': host_port,
                    'host_command': f"ssh -o StrictHostKeyChecking=no -i {ssh_key_path} root@localhost -p {host_port}",
                    'ssh_status': 'Ready'
                })

            except TimeoutError as e:
                app.logger.error(str(e))
                machine_info.append({
                    'container_id': container.id[:12] if container else "Unknown",
                    'host_port': None,
                    'host_command': None,
                    'ssh_status': 'Not Ready'
                })

        session['machine_info'] = machine_info
        return jsonify(machine_info)

    except Exception as e:
        app.logger.error(f"Error in spawn_machines: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route('/run_command', methods=['POST'])
def RUN_COMMAND_ROUTE():
    try:
        command = request.form['command']
        if not command or ';' in command or '&&' in command: # prevent command injection
            return jsonify({"error": "Invalid command."}), 400

        machine_info = session.get('machine_info', [])
        if not machine_info:
            return jsonify({"error": "No machines spawned. Please spawn machines first."}), 400

        ansible_hosts = {
            f"container_{machine['container_id']}": {
                "ansible_host": "localhost",
                "ansible_port": machine['host_port'],
                "ansible_user": "root",
                "ansible_ssh_private_key_file": ssh_key_path,
                "ansible_ssh_extra_args": "-o StrictHostKeyChecking=no"
            }
            for machine in machine_info if machine['ssh_status'] == 'Ready'
        }

        if not ansible_hosts:
            return jsonify({"error": "No ready containers available for command execution."}), 400

        app.logger.info("Running Ansible command on hosts.")
        command_results = run_ansible(ansible_hosts, command)

        for machine in machine_info:
            container_id = f"container_{machine['container_id']}"
            machine['command_result'] = command_results.get(container_id, "N/A (No result)")

        return jsonify(machine_info)

    except Exception as e:
        app.logger.error(f"Error running command: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/<action>_all_containers', methods=['POST'])
def STOP_OR_REMOVE_ALL_CONTAINERS_ROUTE(action):
    try:
        if not session.get('machine_info'): # safeguard against empty session data
            return jsonify({"status": "No machines spawned. Nothing to stop or remove."})

        if action not in ['stop', 'remove']: # validate the action parameter
            return jsonify({"error": f"Invalid action: {action}. Use 'stop' or 'remove'."}), 400

        containers = client.containers.list(all=True, filters={"label": "flask_app=spawned_container"})
        remove_or_stop_containers(containers, action)

        session.pop('machine_info', None)  # clear session data
        return jsonify({"status": f"All containers {'stopped and' if action == 'stop' else ''} removed successfully."})

    except Exception as e:
        app.logger.error(f"Error {'stopping' if action == 'stop' else 'removing' } all containers: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route('/<action>_container', methods=['POST'])
def STOP_OR_REMOVE_CONTAINER_ROUTE():
    try:
        container_id = request.form.get('container_id')
        if not container_id:
            return jsonify({"error": "No container ID provided."}), 400

        container = client.containers.get(container_id)
        remove_or_stop_containers([container], 'stop')

        # Remove the stopped container from the session data
        session['machine_info'] = [machine for machine in session.get('machine_info', []) if machine['container_id'] != container_id]

        return jsonify({"status": f"Container {container_id[:12]} stopped and removed successfully."})

    except docker.errors.NotFound:
        return jsonify({"error": f"Container {container_id[:12]} not found."}), 404
    except Exception as e:
        app.logger.error(f"Error stopping container {container_id[:12]}: {str(e)}")
        return jsonify({"error": str(e)}), 500


## MAIN APP ENTRY POINT ##
if __name__ == '__main__':
    app.run(debug=True)
