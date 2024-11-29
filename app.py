## DEPENDENCIES ##
from flask import Flask, render_template, request, jsonify, session # external
from flask_session import Session # external

import docker, ansible_runner # external
import os, shutil, atexit, signal, json, logging, tempfile # built-in


## GLOBAL CONFIGURATION ##
app = Flask(__name__) # create a Flask app
app.config['SECRET_KEY'] = os.urandom(24) # set a secret key for session management
app.config['SESSION_TYPE'] = 'filesystem' # store session data in 'filesystem'

def clear_session_files(dir = 'flask_session'):
    if os.path.exists(dir):
        shutil.rmtree(dir) # removes the directory and its contents
        app.logger.info("Cleared old Flask session files at startup.")

clear_session_files() # clear old session files at startup
Session(app) # initialize session management

client = docker.from_env() # connect to docker daemon (using default socket)
logging.basicConfig(level=logging.DEBUG) # set logging level to DEBUG (for app.logger)

ssh_key_dir = os.path.expanduser("~/.ssh")
ssh_key_path = os.path.join(ssh_key_dir, "docker_container_key")
public_key_path = ssh_key_path + ".pub"

next_available_port = 22001 # starting port for container SSH mapping
MAX_CONAINER_LIMIT = 100 # maximum number of containers that can be spawned


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
    global next_available_port
    try:        
        container = client.containers.run(
            'debian:bullseye-slim',
            command = f'/bin/bash -c "\
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
                        exec /usr/sbin/sshd -D"',
            detach = True,
            ports = {'22/tcp': next_available_port},  # assign available port for SSH
            tty = True,
            labels = {"flask_app": "spawned_container"} # custom label for faster lookup (docker inspect)
        )

        app.logger.info(f"Container {container.id} spawned successfully on port {next_available_port}")
        next_available_port += 1 # increment port for next container
        return container

    except Exception as e:
        app.logger.error(f"Error spawning container: {str(e)}")
        raise


def get_port_mapping(container):
    """
    Returns the host port mapping for a given container.
    """
    container.reload() # refresh container status
    ports = container.attrs['NetworkSettings']['Ports']
    return None if '22/tcp' not in ports else ports['22/tcp'][0]['HostPort']


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
            os.unlink(file_path) # removes the file


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
            private_data_dir = tempfile.gettempdir(), # set platform-independent '/tmp' directory
            playbook = playbook_file_path,
            inventory = inventory_file_path,
            extravars = {'ansible_ssh_private_key_file': ssh_key_path}
        )

        return parse_ansible_results(result)

    except Exception as e:
        app.logger.error(f"Error running Ansible: {str(e)}")
        raise

    finally:
        cleanup_files([inventory_file_path, playbook_file_path])


def remove_or_stop_containers(containers, action, type='spawned'):
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
            app.logger.warning(f"Failed to {action} {type} container {container.id[:12]}: {str(e)}")


def cleanup(action='remove'):
    """Cleans up all spawned containers and orphaned containers (by stopping or removing them)."""
    containers = client.containers.list(all=True, filters={"label": "flask_app=spawned_container"})
    remove_or_stop_containers(containers, action)

    # [OPTIONAL] remove all orphaned containers (if any, due to previous errors)
    containers = client.containers.list(all=True, filters={"ancestor": "debian:bullseye-slim"})
    remove_or_stop_containers(containers, action, 'orphaned')

    app.logger.info("Cleanup complete.")


## ROUTES (FOR FLASK APP) ##
# HTTP status codes: 200 - OK (default), 400 - Bad Request, 404 - Not Found, 500 - Internal Server Error
@app.route('/')
def MAIN_INDEX_ROUTE():
    return render_template('index.html', machine_info=session.get('machine_info', []))


@app.route('/configure')
def CONFIGURE_ROUTE():
    return render_template('configure.html')


@app.route('/get_machine_info')
def GET_MACHINE_INFO_ROUTE():
    return jsonify(session.get('machine_info', []))


@app.route('/spawn', methods=['POST'])
def SPAWN_MACHINES_ROUTE():
    try:
        num_machines = request.form.get('num_machines', type=int)

        if not isinstance(num_machines, int) or num_machines <= 0: # [OPTIONAL] validation for preventing injection attacks
            return jsonify({"error": "Invalid 'num_machines' value. Must be a positive integer."}), 400
        
        if num_machines > MAX_CONAINER_LIMIT:
            return jsonify({"error": f"Cannot spawn more than {MAX_CONAINER_LIMIT} machines."}), 400
        
        public_key = ensure_ssh_key()
        containers = []  # Track spawned containers
        machine_info = session.get('machine_info', []) # Track machine details for display

        for _ in range(num_machines):
            try:
                container = spawn_container(public_key)                
                host_port = get_port_mapping(container)
                containers.append(container)
                machine_info.append({
                    'container_id': container.id[:12],
                    'host_port': host_port,
                    'host_command': f"ssh -o StrictHostKeyChecking=no -i {ssh_key_path} root@localhost -p {host_port}",
                    'ssh_status': 'Ready'
                })

            except Exception as e: # [NOTE] machine_info needs to be handled properly
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
        if not command: # [OPTIONAL] validation: `or ';' in command or '&&' in command or '|' in command:`, [IMPROVEMENT] use regex patterns
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
            for machine in machine_info if machine['ssh_status'] == 'Ready' # [NOTE] currently, only ready machines are considered, ssh_status is not reliable
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
            return jsonify({"error": "No machines spawned. Nothing to stop or remove."}), 400

        if action not in ['stop', 'remove']: # [OPTIONAL] validate the action parameter
            return jsonify({"error": f"Invalid action: {action}. Use 'stop' or 'remove'."}), 400

        cleanup(action)
        session['machine_info'] = []  # clear session data for spawned containers
        return jsonify({"status": f"All containers stopped {'and removed' if action == 'remove' else ''} successfully."})

    except Exception as e:
        app.logger.error(f"Error {'stopping' if action == 'stop' else 'removing' } all containers: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route('/<action>_container', methods=['POST'])
def STOP_OR_REMOVE_CONTAINER_ROUTE(action):
    try:
        container_id = request.form.get('container_id')
        if not container_id:
            return jsonify({"error": "No container ID provided."}), 400

        container = client.containers.get(container_id)
        remove_or_stop_containers([container], action)

        # remove the stopped/removed container from the session data
        session['machine_info'] = [machine for machine in session.get('machine_info', []) if machine['container_id'] != container_id]

        return jsonify({"status": f"Container {container_id[:12]} stopped {'and removed' if action == 'remove' else ''} successfully."})

    except docker.errors.NotFound:
        return jsonify({"error": f"Container {container_id[:12]} not found."}), 404

    except Exception as e:
        app.logger.error(f"Error {'stopping' if action == 'stop' else 'removing' } container {container_id[:12]}: {str(e)}")
        return jsonify({"error": str(e)}), 500


## EXIT POINT SETUP (FOR CLEANUP) ##
atexit.register(cleanup) #  register 'cleanup' to run when the app quits normally

def handle_sigint(signum, frame):
    """Custom signal handler to catch Ctrl+C (SIGINT) interrupts."""
    app.logger.info("Received SIGINT (Ctrl+C), cleaning up...")
    exit(0) # also calls the 'cleanup' function

def handle_sigstp(signum, frame):
    """Custom signal handler to catch SIGTSTP (Ctrl+Z) interrupts."""
    app.logger.info("Received SIGTSTP (Ctrl+Z), cleaning up...")
    exit(0)

def handle_sigterm(signum, frame):
    """Custom signal handler to catch SIGTERM interrupts."""
    app.logger.info("Received SIGTERM, cleaning up...")
    exit(0)

signal.signal(signal.SIGINT, handle_sigint) # register SIGINT custom handler to run when Ctrl+C is pressed
signal.signal(signal.SIGTSTP, handle_sigstp) # register SIGTSTP custom handler to run when Ctrl+Z is pressed
signal.signal(signal.SIGTERM, handle_sigterm) # register SIGTERM custom handler to run when the app is terminated


## MAIN FLASK APP ENTRY POINT ##
if __name__ == '__main__':
    app.run(debug=True, use_reloader=False) # start the Flask app in debug mode (with auto-reload disabled)
